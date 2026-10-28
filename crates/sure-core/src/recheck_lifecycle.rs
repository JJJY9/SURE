//! Re-check lifecycle and history.
//!
//! SURE does not trust an agent's claim that a finding is fixed. This module
//! compares a new run's findings and check results with the open findings from
//! previous runs, resolves the ones whose re-check checks now pass, and keeps
//! the ones that still have evidence.
//!
//! Every run's findings and check results are stored as records, so a previous
//! run stays auditable even after a finding is closed.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

use sure_domain::finding::{Finding, FindingStatus};
use sure_domain::ids::{CheckId, FindingId, FingerprintId};
use sure_domain::status::{CheckResult, CheckStatus};

use crate::candidate_context::{CandidateContext, classify_path};
use crate::paths::CaseSensitivity;
use crate::store::{RecordKind, Store, StoreError};

/// A stable identity for a finding across runs.
///
/// Finding IDs are minted per run, so the same issue in two runs would look like
/// two different findings. The key is built from the human title and the first
/// checkable evidence anchor, which is what SURE can point a repair at.
///
/// Whether two spellings of a location name **one file** — `src/EMAIL/SEND.rs`
/// and `src/email/send.rs` — decides whether a previous finding matches this
/// run's finding, and that is a fact about the volume the project is on and not
/// about the operating system's name. CI run `35544579833` measured both answers
/// in one workflow: the `rust (macos-latest)` job (`106168109227`) wrote one
/// spelling and read the other back, so they are one file there, while
/// `rust (ubuntu-latest)` (`106168109213`) found two files. So the rule is
/// **passed in** — [`CaseSensitivity`], asked once per run by [`case_rule_for`]
/// — rather than compiled in by a `cfg` on the platform. See
/// [`crate::paths::volume`] for the probe and what it does when it cannot tell.
///
/// The title is kept exact: two findings with the same location but different
/// user-facing descriptions are different issues.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FindingKey {
    title: String,
    location: String,
    locator: String,
}

impl FindingKey {
    /// Build a key from a finding, if the finding has at least one checkable
    /// anchor.
    ///
    /// `case` is the volume's rule for this project, from [`case_rule_for`]. It
    /// is an argument rather than something this function works out, so that one
    /// run asks the volume once for every key it builds, and so that both answers
    /// can be exercised on one machine — see the tests below.
    #[must_use]
    pub fn from_finding(finding: &Finding, case: CaseSensitivity) -> Option<Self> {
        let anchor = finding.evidence.iter().find(|e| e.anchor.is_checkable())?;
        Some(Self::new(
            &finding.title,
            &anchor.anchor.location,
            &anchor.anchor.locator,
            case,
        ))
    }

    fn new(title: &str, location: &str, locator: &str, case: CaseSensitivity) -> Self {
        Self {
            title: title.to_owned(),
            location: normalise_path(location, case),
            locator: normalise_path(locator, case),
        }
    }
}

/// The rule that decides whether two of this project's findings anchor one file.
///
/// **What it asks.** The volume that holds `project_root`, once per run, with the
/// probe [`crate::paths::volume`] documents in full: a name is read from the
/// project root's own listing, its case is flipped, and the volume is asked
/// whether the flipped spelling resolves. Windows folds case in the operating
/// system's name; macOS folds it on the volume Apple ships and can be made to
/// keep it; a Linux mount can be either — CI run `35544579833` measured macOS and
/// Linux answering opposite ways in one workflow.
///
/// **What it does when the volume cannot be asked.** [`CaseSensitivity::Sensitive`]:
/// two spellings are two files. `project_root` that is a file, that does not
/// exist, or that holds nothing whose case can be flipped is answered the same
/// way, and no error is raised — this decides an identity, and refusing to decide
/// would stop a re-check over a question that has a safe answer.
///
/// **Which way it errs.** Toward two findings for one file rather than one
/// finding for two. Folding a volume that keeps case merges two files into one
/// key: this run's spelling is reported, the previous finding is dropped from the
/// verdict as a duplicate, and a problem that exists stops being reported — a
/// false green, which `CLAUDE.md` says is more serious than a visible error. Not
/// folding a volume that folds reports one problem twice, and a previous finding
/// is carried open beside this run's copy of it, which a reader can see.
#[must_use]
pub fn case_rule_for(project_root: &str) -> CaseSensitivity {
    crate::paths::case_rule_of_volume_or_sensitive(Path::new(project_root))
}

/// Whether two spellings name the same project directory.
///
/// The question [`case_rule_for`] answers half of. `case_rule_for` says what
/// this project's volume does with case; this says whether two
/// `project_root` strings name one directory, given that answer. Both are here
/// so that SURE has **one** answer to *when are two paths one project*: the
/// tier a project's events earn ([`crate::capability_report::for_project`]) and
/// the earlier findings a re-check compares against ([`previous_open_findings`])
/// are two readers of one store asking that one question about one field, and a
/// second rule would let them disagree about the same two rows.
///
/// **What it asks.** [`crate::paths::compare::same_path_case`], which is the
/// repository's *are these the same location* predicate and touches no
/// filesystem, plus `case` for the part of it that is a fact about the volume.
/// Everything that is not a case question is decided by the path itself and is
/// therefore decided the same way on every machine:
///
/// - separators: `C:\work\mine` and `C:/work/mine` are one spelling to
///   `Path`'s own parser on Windows, and Windows resolves both;
/// - a trailing separator: `C:\work\mine\` names the directory it is inside;
/// - a `.` segment: `C:\work\.\mine` names `C:\work\mine`;
/// - a `..` segment: folded where it can be, so `C:\work\mine\..\mine` is
///   `C:\work\mine` and `C:\work\mine\..` is **not** — it is `C:\work`;
/// - the drive letter's case: lowercased unconditionally, because Windows has
///   no uppercase `C:` distinct from `c:` and this is not a case-sensitivity
///   decision ([`crate::paths::compare`] says so where it does it);
/// - a verbatim prefix: `\\?\C:\work` and `C:\work` are one location.
///
/// Everything that *is* a case question is `case`'s, and `case` comes from the
/// volume rather than from this machine's name for itself — see
/// [`case_rule_for`] and [`crate::paths::volume`].
///
/// **What it is not.** Not a containment test. `same_path_case` requires both
/// paths to be the same length in components, so `C:\work` is not
/// `C:\work\mine`, `C:\work\mine` is not `C:\work\mine2`, and neither is
/// its own parent. A prefix comparison would match all three, and each of those
/// three is a genuinely different directory whose events would then be counted
/// as this project's.
///
/// **What it does when the two paths cannot be resolved.** Every `&str` is a
/// path, so there is no unresolved case at this level; what can fail is the
/// volume probe, and `case` is where that has already been decided. When the
/// volume cannot be asked — a `project_root` that is a file, that does not
/// exist, that cannot be listed, or that holds nothing whose case can be
/// flipped — [`case_rule_for`] answers [`CaseSensitivity::Sensitive`]. A stored
/// root that cannot be told apart from this one, and two stored roots that
/// differ only in case, are then two projects.
///
/// **Which way that errs.** Toward counting fewer events, never toward counting
/// another project's. The two mistakes are not symmetric, and this is the one
/// place in the product where the asymmetry is a verdict rather than a line:
///
/// - answering [`CaseSensitivity::Insensitive`] about a volume that keeps case
///   makes two genuinely different projects compare equal. This run's report
///   would then count **another project's** session as its own, the tier would
///   rise on evidence that is not about this project at all, and the counted
///   sentence would name it. That is a false green in the product's own voice,
///   and `CLAUDE.md` ranks it above every visible error;
/// - answering [`CaseSensitivity::Sensitive`] about a volume that folds means a
///   project SURE has a session for is reported as one it has never seen — the
///   tier falls to 0 and the notice names the events it did not count, so a
///   careful reader can diagnose it.
///
/// The second is a defect and the first is a false green, so an answer that
/// cannot be had is the second. The two answers agree wherever the volume is
/// the platform's default, which is why the direction costs nothing on the
/// machines this repository runs on.
#[must_use]
pub fn same_project_root(a: &str, b: &str, case: CaseSensitivity) -> bool {
    crate::paths::compare::same_path_case(Path::new(a), Path::new(b), case)
}

/// The form of a path a [`FindingKey`] is built from, under `case`.
///
/// **What it asks**: `case` is the project's volume's answer to *are these two
/// spellings one file*, asked once per run by [`case_rule_for`] and held for the
/// whole of [`reconcile`]'s work. Under [`CaseSensitivity::Insensitive`] the path
/// is lowercased; under [`CaseSensitivity::Sensitive`] only the whitespace around
/// it goes, because on that volume `src/EMAIL/SEND.rs` and `src/email/send.rs`
/// are two files and folding them would report two problems as one.
///
/// **What it costs**: `to_lowercase` walks the text and allocates, and this is
/// called twice per finding, for `location` and `locator`. On a folding volume
/// that pass is what buys the match; on a volume that keeps case the same call
/// site allocates once for `to_owned` and folds nothing. Making the rule a value
/// rather than a `cfg` moves the choice to run time and moves no work with it:
/// the branch is a comparison, and a build for either platform pays the same.
///
/// **Which way it errs**: it cannot — it is handed an answer, and the answer's
/// error direction belongs to [`case_rule_for`] and [`crate::paths::volume`].
fn normalise_path(text: &str, case: CaseSensitivity) -> String {
    let trimmed = text.trim();
    match case {
        CaseSensitivity::Insensitive => trimmed.to_lowercase(),
        CaseSensitivity::Sensitive => trimmed.to_owned(),
    }
}

/// What changed between the previous run and the current run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleUpdate {
    /// Findings to report for the current run. Open findings are first, then
    /// resolved ones, each group most-serious first.
    pub findings: Vec<Finding>,
    /// Findings that were open before and that new evidence resolved.
    pub resolved: Vec<Finding>,
    /// Findings that were open before and stayed open.
    pub kept_open: Vec<Finding>,
}

/// Inputs to the re-check lifecycle.
#[derive(Debug, Clone)]
pub struct LifecycleInputs<'a> {
    /// Open findings from previous runs for the same project.
    pub previous_open: &'a [Finding],
    /// Findings produced by the current run.
    pub current_findings: &'a [Finding],
    /// Outcomes of checks run in this pass.
    pub check_results: &'a [CheckResult],
    /// For each previous finding id, the checks that can observe whether it is
    /// fixed. When a finding has no entry here, its re-check is treated as
    /// absent and the finding stays open unless a current finding matches it.
    pub rechecks: &'a [(FindingId, Vec<CheckId>)],
    /// The checks this run planned, whatever their results.
    ///
    /// Needed to tell a contract check whose subject has disappeared from one
    /// that was planned and not observed: a candidate-driven check
    /// ([`crate::candidate_scanner::is_candidate_check`]) is proposed only
    /// while the marker it was built from is in the project, so "a candidate
    /// check this run did not plan" is the scanner saying the marker is gone —
    /// and that is the one absence that resolves a finding rather than keeping
    /// it open.
    pub planned: &'a [CheckId],
    /// The rule this project's volume applies to two spellings of one path.
    ///
    /// Asked once per run by [`case_rule_for`] and passed in, rather than worked
    /// out per finding or per path: [`FindingKey`] is the only thing that needs
    /// it, and every key in one comparison has to be built by the same rule — a
    /// folded key compared with an unfolded one is how two findings for one file
    /// become one finding for two. See `normalise_path` below for what the answer
    /// does and [`crate::paths::volume`] for what the question is.
    pub case: CaseSensitivity,
}

/// Reconcile previous findings with current findings and check results.
///
/// The returned [`LifecycleUpdate::findings`] are the ones that belong in the
/// current run's verdict:
///
/// - every current finding, reported as `Open`;
/// - every previous open finding that did not reappear but whose re-check
///   checks all passed, reported as `Resolved`;
/// - every previous open finding that did not reappear and whose re-check
///   checks did not all pass, reported as `Open`.
///
/// A previous finding that matches a current finding by key is considered the
/// same issue; the current finding is reported and the previous one is not
/// duplicated. A previous finding with no matching current finding and no
/// passing re-check stays open, because SURE cannot honestly say it was fixed
/// — except when its re-check is a candidate-driven check the current run no
/// longer plans, which is the scanner itself reporting that the marker the
/// finding was about is gone (see [`LifecycleInputs::planned`]).
#[must_use]
pub fn reconcile(
    inputs: LifecycleInputs<'_>,
    current_fingerprint: FingerprintId,
) -> LifecycleUpdate {
    let current_keys: HashMap<FindingKey, &Finding> = inputs
        .current_findings
        .iter()
        .filter_map(|f| FindingKey::from_finding(f, inputs.case).map(|k| (k, f)))
        .collect();

    let result_by_id: HashMap<CheckId, CheckStatus> = inputs
        .check_results
        .iter()
        .map(|r| (r.id.clone(), r.status))
        .collect();

    let recheck_map: HashMap<FindingId, &[CheckId]> = inputs
        .rechecks
        .iter()
        .map(|(id, checks)| (id.clone(), checks.as_slice()))
        .collect();

    let mut findings: Vec<Finding> = inputs.current_findings.to_vec();
    let mut resolved = Vec::new();
    let mut kept_open = Vec::new();

    for previous in inputs.previous_open {
        let Some(key) = FindingKey::from_finding(previous, inputs.case) else {
            // A previous finding with no checkable anchor cannot be matched or
            // resolved; carry it forward as-is so it does not vanish.
            findings.push(clone_for_state(
                previous,
                current_fingerprint.clone(),
                FindingStatus::Open,
            ));
            kept_open.push(previous.clone());
            continue;
        };

        if current_keys.contains_key(&key) {
            // The issue still exists in the current run. The current finding is
            // already in `findings`; the previous one is history.
            kept_open.push(previous.clone());
            continue;
        }

        if recheck_passed(&recheck_map, &result_by_id, inputs.planned, &previous.id) {
            let closed = clone_for_state(
                previous,
                current_fingerprint.clone(),
                FindingStatus::Resolved,
            );
            findings.push(closed.clone());
            resolved.push(closed);
        } else {
            let carried =
                clone_for_state(previous, current_fingerprint.clone(), FindingStatus::Open);
            findings.push(carried.clone());
            kept_open.push(carried);
        }
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    resolved.sort_by_key(|f| std::cmp::Reverse(f.severity));
    kept_open.sort_by_key(|f| std::cmp::Reverse(f.severity));

    LifecycleUpdate {
        findings,
        resolved,
        kept_open,
    }
}

fn recheck_passed(
    recheck_map: &HashMap<FindingId, &[CheckId]>,
    result_by_id: &HashMap<CheckId, CheckStatus>,
    planned: &[CheckId],
    finding_id: &FindingId,
) -> bool {
    let Some(checks) = recheck_map.get(finding_id) else {
        // No re-check list means SURE does not know how to observe a fix.
        return false;
    };
    if checks.is_empty() {
        return false;
    }
    checks.iter().all(|id| {
        if result_by_id.get(id) == Some(&CheckStatus::Pass) {
            return true;
        }
        // A candidate-driven check this run did not plan is the scanner no
        // longer finding the marker the check was built from: the finding's
        // subject has disappeared, which is a resolution and not an absence
        // of evidence (2026-10-14:修复把候选修没后,契约点名的候选检查因
        // 不再被排程而永不可"运行且通过" — the repair loop could otherwise
        // never close a finding the fix genuinely removed). Every other
        // missing check — planned but unobserved, or a fixed check the
        // schedule no longer holds — keeps the finding open, because nothing
        // here observed a fix.
        crate::candidate_scanner::is_candidate_check(id) && !planned.contains(id)
    })
}

fn clone_for_state(
    finding: &Finding,
    fingerprint: FingerprintId,
    status: FindingStatus,
) -> Finding {
    Finding {
        id: FindingId::generate(),
        status,
        fingerprint,
        ..finding.clone()
    }
}

/// How many stored records one read of the earlier runs walks.
///
/// # Why this is a bound with a number rather than `0`
///
/// [`Store::history`] documents `0` as *"returns none"* and the implementation
/// binds it as `LIMIT 0`, so a read that is meant to find the previous run's open
/// findings could only ever return an empty list — and the caller then reports
/// *"no earlier run left anything open"* as a fact about the project rather than
/// as a failure to look. That was this function until `P7-T012`.
///
/// # Why this number
///
/// A bound rather than a promise, in the shape of [`crate::allowance::SCAN_LIMIT`]
/// and for the same reason. **The query is newest-first and the project filter is
/// applied in Rust after the limit**, so the budget is spent before this module
/// knows which of the rows belong to the project it was asked about: any limit
/// that is merely "big enough for this project" silently drops that project's
/// older runs, which is the same failure as `0` with a quieter symptom. The
/// number is therefore chosen against the store rather than against a project —
/// far more runs than any project accumulates between two checks, and a store
/// that reaches it has something wrong with it.
///
/// # The stronger fix, and why it is not this one
///
/// Spending the budget on other projects' rows is the underlying waste, and
/// [`HistoryFilter`](crate::store::HistoryFilter) is why it happens: the filter
/// carries `project_fingerprint` and **no `project_root`**, so this read cannot ask
/// the store for its own project's rows and must filter them in Rust afterwards.
/// Pushing `project_root` into the query would make this bound count *this
/// project's* records and shrink the truncation to a project nobody has 4096
/// findings about. It is deliberately **not** taken here, and this is the paragraph
/// that says so:
///
/// - **It does not remove the need for the check above.** One project's own rows
///   can pass any bound, and the failure direction has to be right whatever the
///   number counts — which is this task's acceptance, not that change's.
/// - **It is a change to a type used well beyond this module.**
///   `git grep -l 'HistoryFilter' crates/` names 19 files — 13 under
///   `sure-core/src`, two core test files and four under `sure-cli` — and each of
///   them would have to decide whether it means a project-scoped scan now.
/// - **It re-decides the number rather than only the plumbing.** A bound of 4096
///   *rows in the store* and a bound of 4096 *rows for one project* are different
///   quantities with different reasons, and the paragraph above argues for the
///   first.
///
/// So it belongs in its own task, with its own number and its own acceptance.
/// Riding along with this one would have changed what every other caller's filter
/// does under cover of a task about failure direction.
///
/// **That is where the resemblance to `allowance::SCAN_LIMIT` ends, and this
/// paragraph used to claim otherwise.** `Store::spend_allowance` reads its bound
/// and then acts on it — `store/mod.rs:583` returns `None` when the scan
/// saturates, and `None` means spend nothing, so an exhausted allowance fails
/// **closed**. The supervisor corrected the false half of that claim in the
/// `P7-T012` acceptance commit, and what it corrected was the *sentence*: the
/// number is the same and the failure direction was opposite, because a bound that
/// fails in `spend_allowance` makes SURE *do* less while a bound that failed here
/// made SURE *claim* less is wrong — a false green rather than a refusal. The
/// correction could not repair the behaviour, because [`previous_open_findings`]
/// had no check for a correction to add to; **`P15-T029` added one**, and the
/// direction now matches `spend_allowance`'s: a scan that stops at this bound
/// returns [`HistoryReadError::ScanStoppedEarly`], which `pipeline::recheck`
/// reports as stage 12 not running with that error as the detail, so reaching the
/// bound makes SURE do less and the reassuring answer is the one it will not give.
///
/// The 4096 is still a judgement about scale: no fixture or test was found that
/// reaches it in practice, and none is claimed here. What `P15-T029` added is a
/// test that reaches it **on purpose** and a read that fails closed when it does.
///
/// # What this bound does not affect, so that it is not rediscovered
///
/// **Nothing consumes [`LifecycleUpdate::findings`]** — checked, not assumed:
/// `git grep -n 'lifecycle' crates/` finds the field declared at `:135`, produced
/// by `pipeline::recheck`, carried on `RunOutcome.lifecycle` (`pipeline.rs:461`),
/// and read by callers that take `kept_open` and `resolved` only (the CLI's human
/// line and machine frame for stage 12; `pipeline.rs`'s own detail in
/// `recheck`). So the blast radius of a truncation used to be bounded to the
/// `Against the earlier run: N finding(s) still open` line and stage 12's detail,
/// and never reached `run.verdict.findings`, the open-finding counts or hand-off
/// readiness. **That bound on the damage is what changed first**: a saturated scan
/// now makes stage 12 not run, so the two lines a reader would have got are absent
/// rather than short — and because `StageOutcome::NotRun` is a gap,
/// [`crate::pipeline::PipelineOutcome::is_green`] is false for that run. Whoever
/// gives `LifecycleUpdate::findings` a consumer inherits the reason this read
/// refuses instead of answering.
pub const HISTORY_SCAN_LIMIT: usize = 4096;

/// Why the read of what an earlier run left open could not answer.
///
/// Two ways, and the second is the one this type exists for. A store that cannot
/// answer its own query is [`StoreError`] carried through rather than restated, for
/// the reason `crate::paths::PathError` gives for the same choice: one wording for
/// one condition. A scan that reached its bound is not a store failure at all — the
/// store answered, and what it answered with is exactly as much as the bound
/// allowed, which may or may not be everything — so it needs a variant of its own,
/// because reporting it as a store failure would send a reader looking for a
/// damaged file that is not damaged.
///
/// **Why this is an error and not a flag on a short list.** A list that stopped at
/// a bound is indistinguishable, to its caller, from a list that was read to the
/// end and found nothing: `previous_open_findings` would answer `Ok(vec![])` for a
/// project whose earlier run left something open, whenever that project's rows
/// sort past the bound. That is the failure `CLAUDE.md` ranks above every other —
/// *"a false green is more serious than a visible error"* — and the way out is the
/// one `Store::spend_allowance` takes at `store/mod.rs:583`: refuse.
///
/// **The other precedent in this tree, and why it is not the one followed.**
/// [`crate::capability_report`] reads a store with `EVENT_SCAN_LIMIT` and, when the
/// scan reaches it, **succeeds with `CapabilityEvidence::truncated` set**
/// (`capability_report.rs:234`); the flag is a field on the report and adds a
/// sentence beside the number it qualifies — *"SURE stopped before it had read every
/// event the store holds, so anything older than the events it read is not counted
/// here"* (`sure_domain::capability:281`). **What a flag would cost here is two
/// things that precedent does not have to pay.** The count this read produces is
/// composed away from the read: the CLI's `Against the earlier run: N finding(s)
/// still open` line is `LifecycleUpdate::kept_open.len()`, so the caveat would have
/// to be carried through `reconcile` and out to every caller that prints the number
/// or it would be a flag nobody reads. And a stage that ran with a caveat is a
/// stage that **ran**, so `PipelineOutcome::is_green` would be true for a run whose
/// comparison with the previous run was built from a list that stopped early — the
/// false green again, one level up. Refusing uses the plumbing that already turns an
/// `Err` here into [`crate::pipeline::StageOutcome::NotRun`], and a stage that did
/// not run is a gap, which is what makes the run not green.
#[derive(Debug)]
pub enum HistoryReadError {
    /// The store could not answer the query.
    Store(StoreError),
    /// The scan reached its bound, so the list it built may be short for a reason
    /// it cannot show. Not "there was more than this": at exactly the bound SURE
    /// cannot tell, which is why the message says so rather than claiming it.
    ScanStoppedEarly {
        /// The bound the scan stopped at.
        limit: usize,
        /// The project the read was about, so the message can name it.
        project_root: String,
    },
}

impl From<StoreError> for HistoryReadError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl fmt::Display for HistoryReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "{error}"),
            Self::ScanStoppedEarly {
                limit,
                project_root,
            } => {
                // Singular for the bound as well as the count, the way
                // `sure_domain::capability` does it for the events it counts: the
                // bound is 4096 in production and a test may set it to 1, and a
                // message that reads "1 records" is one a reader has to interpret.
                let records = if *limit == 1 { "record" } else { "records" };
                write!(
                    f,
                    "SURE stopped reading its history at its bound of {limit} {records}, so it did \
                     not read far enough to know what an earlier run left open for {project_root}.\n\n\
                     A bound reached is not a history read to its end, and the two cannot be told \
                     apart from the list: one cut short at the bound comes back looking exactly like \
                     a list of a project with nothing open, and \"nothing was left open\" is the \
                     answer SURE will not guess.\n\n\
                     This read wrote nothing, and this run has no comparison against an earlier one \
                     rather than a comparison that stopped early."
                )
            }
        }
    }
}

impl std::error::Error for HistoryReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::ScanStoppedEarly { .. } => None,
        }
    }
}

/// Read every open finding for `project_root` from earlier runs.
///
/// Open here means [`FindingStatus::needs_attention`]: `Open` and
/// `CannotConfirm`. Resolved and accepted findings are not carried forward.
///
/// # One entry per finding, not one per row
///
/// [`store_run`] writes **every** finding on **every** run, so a project checked
/// five times has five stored rows per open finding. Returning them all made the
/// re-check report a count that grew with how often the project had been looked
/// at rather than with how many problems it had — measured, before this rule
/// existed: three runs over one unchanged project, and the third said `6 earlier
/// finding(s) stayed open` for three findings.
///
/// The identity to deduplicate on is [`FindingKey`], because the id is minted per
/// run — that is what the key exists for. [`Store::history`] returns newest-first,
/// so the record kept is the most recent reading of that finding. A finding with
/// no key at all (nothing a reader could be pointed at) is **kept rather than
/// dropped**: SURE cannot tell two of them apart, so it cannot choose between them
/// without discarding a record it has no basis to call a duplicate.
///
/// **`case` decides how much that deduplication takes out**, and it is the same
/// rule [`reconcile`] matches by — the caller asks the volume once per run
/// ([`case_rule_for`]) and hands the one answer to both, because two rules here
/// would mean a finding this function dropped as a duplicate reappearing as a
/// finding of its own one call later. On a volume that folds case, a stored
/// `src/EMAIL/SEND.rs` and a stored `src/email/send.rs` are one finding and the
/// newer row wins; on a volume that keeps it they are two, because they are two
/// files.
///
/// # Which rows are this project's
///
/// A row is this project's when its stored `project_root` and this run's
/// `project_root` name one directory, which is [`same_project_root`]'s question
/// rather than a string comparison — the same spelling rule, and the same
/// `case`, that the deduplication below matches findings by. A run started from
/// `C:/projects/sendmail` after one started from `C:\projects\sendmail` is the
/// same project asked about twice, and answering it with "no earlier run left
/// anything open" would be the same false statement about the store that
/// `crate::capability_report` refuses to make about the tier.
///
/// # Why there is no project-state filter
///
/// There was one, and it could never fire: it skipped a record whose
/// `project_fingerprint` equalled the current run's, but a
/// [`ProjectFingerprint`](sure_domain::vocabulary::ProjectFingerprint) carries a
/// **minted** id beside its content digest, so two runs over identical bytes carry
/// two different ids. The comparison is now gone rather than corrected to
/// [`matches`](sure_domain::vocabulary::ProjectFingerprint::matches), because
/// filtering by state would drop exactly the findings a re-check is for: a finding
/// an earlier run left open against the state the project is still in is the one a
/// reader most needs to see. Deduplicating on the key bounds the list; the state
/// it was raised against does not make it any less open.
///
/// # Errors
///
/// [`HistoryReadError::ScanStoppedEarly`] when the scan reached
/// [`HISTORY_SCAN_LIMIT`] and there was more history behind it — see the constant's
/// own comment for why that is a refusal rather than a short list.
/// [`HistoryReadError::Store`] wraps any other failure: [`StoreError::MalformedRow`]
/// when a stored finding does not decode, and whatever the store returns for a
/// query it cannot answer.
pub fn previous_open_findings(
    store: &Store,
    project_root: &str,
    case: CaseSensitivity,
) -> Result<Vec<Finding>, HistoryReadError> {
    Ok(
        previous_open_findings_with_times(store, project_root, case)?
            .into_iter()
            .map(|(finding, _)| finding)
            .collect(),
    )
}

/// The same read as [`previous_open_findings`], with the moment each finding
/// was written down.
///
/// The time is the `written_at_ms` of the **row the finding was read from** —
/// under the deduplication [`previous_open_findings`] documents, the newest row
/// for that finding — not the finding's own timestamp, which a stored document
/// does not carry. It is what [`repair_writes_since`] measures from: a file
/// written before that row was stored was written before the run that last saw
/// this finding open, and is not part of any repair of it.
///
/// One time per finding, in the same order and with the same deduplication as
/// [`previous_open_findings`], because the two are one read and must not be able
/// to disagree about which rows exist.
///
/// # Errors
///
/// As [`previous_open_findings`].
pub fn previous_open_findings_with_times(
    store: &Store,
    project_root: &str,
    case: CaseSensitivity,
) -> Result<Vec<(Finding, i64)>, HistoryReadError> {
    previous_open_findings_within(store, project_root, case, HISTORY_SCAN_LIMIT)
}

/// The same read, with the bound supplied instead of the constant.
///
/// Private, and the bound is the only reason it exists. The branch this read fails
/// on is *reaching* the bound, and a test that cannot move the bound cannot reach
/// it without writing [`HISTORY_SCAN_LIMIT`] rows into a store — which one test
/// does, to drive the number production actually uses, and which the edge cases
/// below cannot each do. So the bound is an argument here and the constant is the
/// one production call site passes: the tests drive the same code path production
/// does, at a size they can afford, rather than a copy of it that could disagree.
///
/// **`limit` is `HISTORY_SCAN_LIMIT` in every production call**, and the two are
/// kept in step by [`previous_open_findings`] being the only caller: a second
/// public entry point taking a limit would be a way to read this history with a
/// bound nobody chose, which is the thing the constant exists to prevent.
fn previous_open_findings_within(
    store: &Store,
    project_root: &str,
    case: CaseSensitivity,
    limit: usize,
) -> Result<Vec<(Finding, i64)>, HistoryReadError> {
    let filter = crate::store::HistoryFilter {
        project_fingerprint: None,
        kind: Some(RecordKind::Document(
            sure_protocol::documents::DocumentKind::Finding,
        )),
        include_recordings: false,
    };
    let records = store.history(&filter, limit)?;

    // The bound was reached, and that is all this can know: the query is
    // newest-first and the project filter runs *below*, so the rows in hand are
    // not this project's rows. `>=` rather than `>` matches
    // `Store::spend_allowance` (`store/mod.rs:583`) rather than being cleverer
    // than it: a store holding exactly `limit` records may have been read to the
    // end, and refusing then loses a comparison the reader could have had — but
    // the other side of that off-by-one is an empty list that means "nothing was
    // left open" about a project SURE never reached, and this repository ranks
    // that false green above this refusal. The refusal is visible and says so;
    // the false green is neither.
    if records.len() >= limit {
        return Err(HistoryReadError::ScanStoppedEarly {
            limit,
            project_root: project_root.to_owned(),
        });
    }

    let mut seen: HashSet<FindingKey> = HashSet::new();
    let mut findings = Vec::new();
    for record in records {
        // Which rows are this project's is decided by [`same_project_root`], the
        // same rule and the same `case` the deduplication below matches findings
        // by: two readers of one store asking *when are two paths one project*
        // must not answer it two ways, or a row this filter took as another
        // project's would be a row the reader was owed.
        if !record
            .project_root
            .as_deref()
            .is_some_and(|recorded| same_project_root(recorded, project_root, case))
        {
            continue;
        }
        let finding: Finding = record.decode()?;
        if !finding.status.needs_attention() {
            continue;
        }
        if let Some(key) = FindingKey::from_finding(&finding, case)
            && !seen.insert(key)
        {
            continue;
        }
        findings.push((finding, record.written_at_ms));
    }
    Ok(findings)
}

/// How many stored events one repair-write read walks.
///
/// A bound for the same reason [`HISTORY_SCAN_LIMIT`] has one: this is a read of
/// a store that another project's sessions share, and the project filter runs in
/// Rust after the limit. It is larger than `HISTORY_SCAN_LIMIT` because it counts
/// *events*, and one AI session records far more events than findings — the MiQi
/// acceptance runs of 2026-10-27 to 2026-10-28 recorded more than a thousand
/// session events for a handful of findings.
///
/// **Reaching it turns the filter off rather than answering short.** A
/// [`RepairWrites`] whose `complete` is false is never [`RepairWrites::is_test_only`],
/// so a truncated scan leaves every finding's status exactly as the check results
/// made it — the behaviour before this filter existed. It does not close
/// anything the evidence in hand does not cover, and it does not invent a
/// refusal either.
pub const REPAIR_WRITE_SCAN_LIMIT: usize = 10_000;

/// What SURE recorded as written for a project since a finding was stored.
///
/// `files` holds the project-relative paths of the writes and deletions SURE
/// could place inside the project, oldest first. `tests_only` is whether every
/// one of those paths is a test file by [`classify_path`]'s reading — the clause
/// in a repair contract is about changing the *test*, so a write SURE reads as
/// anything else counts against it. `complete` is whether the read could account
/// for every event it examined: a malformed event document or a scan that
/// stopped at [`REPAIR_WRITE_SCAN_LIMIT`] leaves it false, because a list that
/// may be short cannot support the statement "only tests changed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairWrites {
    /// Project-relative paths of files written or deleted, oldest first.
    pub files: Vec<String>,
    /// Whether every recorded change is a test file.
    pub tests_only: bool,
    /// Whether the read could account for every event in the window.
    pub complete: bool,
}

impl RepairWrites {
    /// Whether SURE positively saw test files changed and nothing else — at
    /// least one write, every one of them a test, and a complete read.
    ///
    /// An empty list is not this: with nothing recorded, SURE cannot tell a real
    /// fix from one that was never observed, and this filter says nothing about
    /// it. `complete` has to be true for the same reason in the other direction:
    /// a list that may be missing the production write must not be read as one
    /// that contains none.
    #[must_use]
    pub fn is_test_only(&self) -> bool {
        self.complete && self.tests_only && !self.files.is_empty()
    }
}

/// Read the file changes SURE recorded for `project_root` since each earlier
/// finding was stored.
///
/// The changes are `file.*` events — writes, edits and deletions as the
/// normalizers name them (`file.write`, `file.written`) — because those are the
/// only recorded facts that say which files a repair touched. A file *read* is
/// not a change, and an event that names no path cannot be placed and makes that
/// finding's entry incomplete rather than being guessed at.
///
/// Events are matched to this project by the record's own `project_root`, the
/// same rule [`crate::claim_checker`] uses when it asks which events support a
/// claim, and the same `case`. A finding's window opens at the moment its row was
/// stored ([`previous_open_findings_with_times`]): a write recorded before that
/// was made before the run that last saw the finding open, and is not part of a
/// repair of it. The window is inclusive at the bound because nothing in the
/// store orders two rows within one millisecond.
///
/// # Errors
///
/// [`HistoryReadError::Store`] when the store cannot answer the query. Malformed
/// event documents are not an error here: they set `complete = false` for the
/// findings whose window contains them, which turns the filter off for exactly
/// the findings whose evidence could not be read.
pub fn repair_writes_since(
    store: &Store,
    project_root: &str,
    case: CaseSensitivity,
    previous_open: &[(Finding, i64)],
) -> Result<HashMap<FindingKey, RepairWrites>, HistoryReadError> {
    repair_writes_since_within(
        store,
        project_root,
        case,
        previous_open,
        REPAIR_WRITE_SCAN_LIMIT,
    )
}

/// The same read, with the bound supplied instead of the constant.
///
/// Private, and the bound is the only reason it exists — the same arrangement
/// [`previous_open_findings_within`] documents: the branch this read has to get
/// right is *reaching* the bound, a test cannot reach 10 000 events cheaply, and
/// a test that drove a copy of this code instead of the code itself could agree
/// with the copy and not with production.
fn repair_writes_since_within(
    store: &Store,
    project_root: &str,
    case: CaseSensitivity,
    previous_open: &[(Finding, i64)],
    limit: usize,
) -> Result<HashMap<FindingKey, RepairWrites>, HistoryReadError> {
    let mut writes: HashMap<FindingKey, RepairWrites> = HashMap::new();
    for (finding, _) in previous_open {
        if let Some(key) = FindingKey::from_finding(finding, case) {
            writes.insert(
                key,
                RepairWrites {
                    files: Vec::new(),
                    tests_only: true,
                    complete: true,
                },
            );
        }
    }
    let Some(earliest) = previous_open.iter().map(|(_, time)| *time).min() else {
        return Ok(writes);
    };
    if writes.is_empty() {
        // No earlier finding has an anchor, so no finding could be resolved or
        // could be kept open for this reason either. Do not spend the read.
        return Ok(writes);
    }

    let filter = crate::store::HistoryFilter {
        project_fingerprint: None,
        kind: Some(RecordKind::Document(
            sure_protocol::documents::DocumentKind::Event,
        )),
        include_recordings: false,
    };
    let records = store.history_since(&filter, earliest, limit)?;
    let truncated = records.len() >= limit;

    for record in &records {
        if !record
            .project_root
            .as_deref()
            .is_some_and(|recorded| same_project_root(recorded, project_root, case))
        {
            continue;
        }
        let change = match record.decode::<sure_protocol::event::EventEnvelope>() {
            Ok(envelope) => change_of(&envelope, project_root, case),
            // An event this build cannot read may name any file. Mark the
            // windows it falls in as incomplete rather than skipping it: a
            // skipped write could be the production change that makes a test-only
            // list read as test-only.
            Err(_) => FileChange::Unknown,
        };
        for (finding, since_ms) in previous_open {
            if record.written_at_ms < *since_ms {
                continue;
            }
            let Some(key) = FindingKey::from_finding(finding, case) else {
                continue;
            };
            let Some(writes) = writes.get_mut(&key) else {
                continue;
            };
            match &change {
                FileChange::Ignored | FileChange::Outside => {}
                FileChange::Unknown => writes.complete = false,
                FileChange::InProject(relative) => {
                    writes.files.push(relative.clone());
                    if !is_test_file(relative) {
                        writes.tests_only = false;
                    }
                }
            }
        }
    }

    if truncated {
        for writes in writes.values_mut() {
            writes.complete = false;
        }
    }
    Ok(writes)
}

/// One event's answer to *did this change a file, and which one*.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileChange {
    /// Not a file event, or a file event that reports a read.
    Ignored,
    /// The event names no path, so its change cannot be placed.
    Unknown,
    /// A change to a path outside the project.
    Outside,
    /// A change to this project-relative path, with `/` separators.
    InProject(String),
}

fn change_of(
    envelope: &sure_protocol::event::EventEnvelope,
    project_root: &str,
    case: CaseSensitivity,
) -> FileChange {
    let event_type = envelope.event_type.as_str();
    if !event_type.contains("file") {
        return FileChange::Ignored;
    }
    // The same reading `recording_projection::project_file` applies to a file
    // event, widened with the names the normalizers actually produce for a
    // change: MiQi writes `file.written` and Cursor writes `file.edited`, and an
    // edit is as much a change as a write. `file.read` and the other file events
    // a harness may send stay reads.
    let payload = &envelope.payload;
    let deleted = payload.get("deleted").and_then(serde_json::Value::as_bool) == Some(true)
        || event_type.contains("delete");
    let written = payload.get("written").and_then(serde_json::Value::as_bool) == Some(true)
        || payload.get("operation").and_then(serde_json::Value::as_str) == Some("write")
        || ["write", "edit", "creat", "modif", "chang"]
            .iter()
            .any(|marker| event_type.contains(marker));
    if !deleted && !written {
        return FileChange::Ignored;
    }
    let Some(path) = payload.get("path").and_then(serde_json::Value::as_str) else {
        return FileChange::Unknown;
    };
    match relative_to_project(path, project_root, case) {
        Some(relative) => FileChange::InProject(relative),
        None => FileChange::Outside,
    }
}

/// Whether a project-relative path is a test file — the question the contract
/// clause *"changing only the test or assertion"* turns on.
///
/// [`classify_path`] answers a different and deliberately stricter question:
/// which context a *candidate finding* came from. Its own tests pin
/// `src/test_helper.rs` as product, because a helper in product code that
/// happens to be named `test_…` must not silently demote a finding about it.
/// The repair guard needs the other direction: a root-level `test_totals.py` is
/// a pytest test, and reading it as product lets "changed only the test" close
/// a finding unnoticed — measured in the 2026-10-28 MiQi repair-loop retest,
/// where the subagent edited exactly that file and the finding still closed.
///
/// So this keeps [`classify_path`]'s answer and adds the file-name conventions
/// that are test code by name: `test_…`, `…_test`, `…-test` and the bare
/// `test`/`tests` stem, plus pytest's `conftest.py`. The stem has to match a
/// whole segment, so `testing.py`, `contest.py` and `latest.py` stay product.
///
/// The two rules disagree on purpose for a file like `src/test_helper.rs`,
/// which is product to a candidate finding and test code to this guard. The
/// directions are not symmetric: reading a product file as a test keeps a
/// finding open (visible and correctable), while reading a test file as product
/// closes it — the false green this guard exists to prevent.
fn is_test_file(relative: &str) -> bool {
    let path = Path::new(relative);
    if classify_path(path, Path::new(""), None) == CandidateContext::Test {
        return true;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lower = name.to_lowercase();
    if lower == "conftest.py" {
        return true;
    }
    // The stem is the part before the first extension: `test_totals` from
    // `test_totals.py`, `totals_test` from `totals_test.py`. `classify_path`
    // already reads dotted segments (`foo.test.js`), so this is only about
    // underscore- and hyphen-joined names.
    let stem = lower.split('.').next().unwrap_or(lower.as_str());
    matches!(stem, "test" | "tests")
        || stem.starts_with("test_")
        || stem.starts_with("test-")
        || stem.ends_with("_test")
        || stem.ends_with("-test")
}

/// `path` relative to `project_root` with `/` separators, or `None` when it is
/// outside the project or cannot be placed inside it.
///
/// The path arrives as text from a harness, so both separators may appear and
/// the harness's drive and folder names may be spelt with different case than
/// the root's. Case is compared by the same [`CaseSensitivity`] rule the rest of
/// this module matches paths by, except that a drive letter is always compared
/// without case — Windows has no `D:` distinct from `d:` and that is not a
/// case-sensitivity fact. `..` segments are folded where they can be; a path
/// that climbs out of the root is outside the project, because a write there
/// cannot be a change to this project's product code.
fn relative_to_project(path: &str, project_root: &str, case: CaseSensitivity) -> Option<String> {
    let path = path.replace('\\', "/");
    let root = project_root.replace('\\', "/");
    let mut rest = path_components(&path);
    if is_absolute(&path) {
        if !is_absolute(&root) {
            return None;
        }
        let root_parts = path_components(&root);
        if root_parts.is_empty() || rest.len() < root_parts.len() {
            return None;
        }
        if !root_parts
            .iter()
            .zip(rest.iter())
            .all(|(a, b)| same_component(a, b, case))
        {
            return None;
        }
        rest = rest[root_parts.len()..].to_vec();
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in rest {
        if part == ".." {
            parts.pop()?;
        } else {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

fn path_components(text: &str) -> Vec<&str> {
    text.split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect()
}

fn is_absolute(text: &str) -> bool {
    text.starts_with('/')
        || text
            .split('/')
            .next()
            .is_some_and(|first| first.len() == 2 && first.ends_with(':'))
}

fn same_component(a: &str, b: &str, case: CaseSensitivity) -> bool {
    if a.len() == 2 && b.len() == 2 && a.ends_with(':') && b.ends_with(':') {
        return a.eq_ignore_ascii_case(b);
    }
    match case {
        CaseSensitivity::Sensitive => a == b,
        CaseSensitivity::Insensitive => a.to_lowercase() == b.to_lowercase(),
    }
}

/// Keep a finding open when the only repair SURE saw was to its test.
///
/// [`reconcile`] closes a finding when every check its repair contract named
/// passed. For a finding whose strongest evidence is a deterministic check, a
/// passing check is not enough on its own when every file SURE recorded as
/// written since the earlier run is a test file: the contract forbids changing
/// the test rather than the behaviour, and a re-check that accepted that would
/// green a repair which changed nothing the check was about. This is where that
/// contract clause is enforced rather than stated.
///
/// The move is deliberately narrow:
///
/// - only findings whose contract carries that clause
///   ([`sure_domain::repair::requires_production_change`]) are considered;
/// - only when [`RepairWrites::is_test_only`] holds — SURE saw at least one
///   write, every write it saw is a test file, and it read every event it
///   looked at. With no recorded change, or with a write it could not place,
///   SURE has no basis to contradict the check result and the close stands;
/// - a single recorded write SURE reads as anything other than a test is enough
///   for the close to stand, so a real fix is never held open by an
///   accompanying test edit.
///
/// Returns the update with the affected findings reopened (their status is the
/// only field changed) and the reopened findings themselves, so the stage can
/// say how many there were and why.
#[must_use]
pub fn keep_test_only_fixes_open(
    mut update: LifecycleUpdate,
    writes: &HashMap<FindingKey, RepairWrites>,
    case: CaseSensitivity,
) -> (LifecycleUpdate, Vec<Finding>) {
    let mut reopened = Vec::new();
    let mut still_resolved = Vec::new();
    for finding in std::mem::take(&mut update.resolved) {
        let test_only = sure_domain::repair::requires_production_change(&finding)
            && FindingKey::from_finding(&finding, case)
                .and_then(|key| writes.get(&key))
                .is_some_and(RepairWrites::is_test_only);
        if !test_only {
            still_resolved.push(finding);
            continue;
        }
        if let Some(slot) = update.findings.iter_mut().find(|f| f.id == finding.id) {
            slot.status = FindingStatus::Open;
        }
        let open = Finding {
            status: FindingStatus::Open,
            ..finding
        };
        update.kept_open.push(open.clone());
        reopened.push(open);
    }
    update.resolved = still_resolved;

    let by_severity = |finding: &Finding| std::cmp::Reverse(finding.severity);
    update.findings.sort_by_key(by_severity);
    update.kept_open.sort_by_key(by_severity);
    update.resolved.sort_by_key(by_severity);
    (update, reopened)
}

/// Persist a run's findings and check results so later runs can compare.
pub fn store_run(
    store: &Store,
    project_root: &str,
    fingerprint: &FingerprintId,
    findings: &[Finding],
    check_results: &[CheckResult],
) -> Result<RunRecord, StoreError> {
    let mut finding_rows = Vec::new();
    for finding in findings {
        let document = serde_json::to_value(finding).map_err(|error| StoreError::MalformedRow {
            id: 0,
            message: error.to_string(),
        })?;
        let row = store.append_for(
            RecordKind::Document(sure_protocol::documents::DocumentKind::Finding),
            &document,
            project_root,
            fingerprint,
        )?;
        finding_rows.push(row);
    }

    let mut check_result_rows = Vec::new();
    for result in check_results {
        let document = serde_json::to_value(result).map_err(|error| StoreError::MalformedRow {
            id: 0,
            message: error.to_string(),
        })?;
        let row = store.append_for(
            RecordKind::Document(sure_protocol::documents::DocumentKind::CheckResult),
            &document,
            project_root,
            fingerprint,
        )?;
        check_result_rows.push(row);
    }

    Ok(RunRecord {
        finding_rows,
        check_result_rows,
    })
}

/// Identifiers of a stored run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    pub finding_rows: Vec<i64>,
    pub check_result_rows: Vec<i64>,
}

/// The findings from a run that are still open and relevant to the next run.
///
/// This is a convenience over [`reconcile`] for callers that only need the
/// current open set and not the resolved/new split.
pub fn open_after_reconcile(
    inputs: LifecycleInputs<'_>,
    current_fingerprint: FingerprintId,
) -> Vec<Finding> {
    reconcile(inputs, current_fingerprint)
        .findings
        .into_iter()
        .filter(|f| f.status.needs_attention())
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    // Every `LifecycleInputs` below states its case rule as
    // `CaseSensitivity::Sensitive` unless the test is *about* the rule. That is
    // what `case_rule_for` answers when a volume cannot be asked
    // (`paths::volume`), so a test that is about something else never has two
    // spellings folded together underneath it, and the tests that are about the
    // rule say so in their own names.
    use super::*;
    use sure_domain::evidence::{AnchorSubject, Evidence, EvidenceAnchor, EvidenceClass};
    use sure_domain::finding::{
        AssessmentSource, FindingBuilder, FindingStatus, SeverityRationale,
    };
    use sure_domain::ids::{CheckId, FingerprintId};
    use sure_domain::severity::Severity;

    fn fingerprint() -> FingerprintId {
        FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddee").unwrap()
    }

    fn another_fingerprint() -> FingerprintId {
        FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddef").unwrap()
    }

    /// A store under `target/tmp`, git-ignored and on the same volume as the
    /// checkout. The name carries the process id for the reason `store/mod.rs`'s
    /// copy of this helper records in full: freshness must not depend on a
    /// deletion succeeding, because on Windows a file another process holds
    /// cannot be deleted and the failure is easy to swallow.
    fn store_in(name: &str) -> Store {
        let dir = crate::store::scratch_root().join(format!("{name}-{}", std::process::id()));
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("cannot clear {}: {error}", dir.display()),
        }
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        Store::open_at(&dir.join("sure.db")).expect("the store opens")
    }

    fn finding_with(title: &str, location: &str, status: FindingStatus) -> Finding {
        let fp = fingerprint();
        FindingBuilder::new(
            AssessmentSource::DeterministicCheck,
            SeverityRationale::BlocksHandOff,
        )
        .id(FindingId::generate())
        .title(title)
        .severity(Severity::MustFix)
        .status(status)
        .explanation("the send path returns before the provider is called")
        .user_impact("users believe a message was delivered")
        .next_step("call the provider")
        .fingerprint(fp.clone())
        .evidence(vec![Evidence::new(
            EvidenceClass::DeterministicCheck,
            "the send path returns before the provider is called",
            EvidenceAnchor::new(AnchorSubject::File, location, "line 42"),
            Some(fp),
            Severity::MustFix,
        )])
        .build()
        .expect("fixture finding is valid")
    }

    #[test]
    fn a_new_finding_is_reported_open() {
        let new = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let update = reconcile(
            LifecycleInputs {
                previous_open: &[],
                current_findings: std::slice::from_ref(&new),
                check_results: &[],
                rechecks: &[],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings.len(), 1);
        assert_eq!(update.findings[0].id, new.id);
        assert_eq!(update.findings[0].status, FindingStatus::Open);
        assert!(update.resolved.is_empty());
        assert!(update.kept_open.is_empty());
    }

    #[test]
    fn a_reappearing_finding_is_kept_open() {
        let previous = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let current = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: std::slice::from_ref(&current),
                check_results: &[],
                rechecks: &[],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings.len(), 1);
        assert_eq!(update.findings[0].id, current.id);
        assert_eq!(update.findings[0].status, FindingStatus::Open);
        assert_eq!(update.kept_open.len(), 1);
        assert_eq!(update.kept_open[0].id, previous.id);
        assert!(update.resolved.is_empty());
    }

    /// 2026-10-14:修复把候选修没后,契约点名的候选检查(以候选所在文件为
    /// 构造输入)不再被排程——"这个候选检查本轮没被计划"正是扫描器在说
    /// "标记已消失",是解决而非证据缺席;否则"真修好了"永远无法关闭发现项。
    #[test]
    fn a_candidate_check_the_run_no_longer_plans_resolves_the_finding() {
        let previous = finding_with("TODO left in code", "src/pay.py", FindingStatus::Open);
        let candidate_check = crate::checks::check_id("src/pay.py", "candidatetodo");
        let rechecks = vec![(previous.id.clone(), vec![candidate_check])];
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: &[],
                check_results: &[],
                rechecks: &rechecks,
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.resolved.len(), 1);
        assert_eq!(update.resolved[0].status, FindingStatus::Resolved);
        assert_eq!(update.resolved[0].title, previous.title);
        assert!(update.kept_open.is_empty());
    }

    /// 对照组:候选检查被排程了却没有结果(计划了、没观测到)——不是"目标
    /// 消失",必须保持打开,防止把"没跑"当成"过了"。
    #[test]
    fn a_planned_candidate_check_without_a_result_keeps_the_finding_open() {
        let previous = finding_with("TODO left in code", "src/pay.py", FindingStatus::Open);
        let candidate_check = crate::checks::check_id("src/pay.py", "candidatetodo");
        let rechecks = vec![(previous.id.clone(), vec![candidate_check.clone()])];
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: &[],
                check_results: &[],
                rechecks: &rechecks,
                planned: std::slice::from_ref(&candidate_check),
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert!(update.resolved.is_empty());
        assert_eq!(update.kept_open.len(), 1);
    }

    /// 对照组:缺席的不是候选检查(普通固定检查不在计划里)——老规矩,保持
    /// 打开;本次改动不放松其它检查的缺席语义。
    #[test]
    fn an_unplanned_check_that_is_not_a_candidate_keeps_the_finding_open() {
        let previous = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let other_check = crate::checks::check_id("src/email/send.rs", "tests");
        let rechecks = vec![(previous.id.clone(), vec![other_check])];
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: &[],
                check_results: &[],
                rechecks: &rechecks,
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert!(update.resolved.is_empty());
        assert_eq!(update.kept_open.len(), 1);
    }

    #[test]
    fn a_previous_finding_with_passing_rechecks_is_resolved() {
        let previous = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let recheck = CheckId::generate();
        let check_result = CheckResult::pass(
            recheck.clone(),
            "email send check",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            another_fingerprint(),
        );
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: &[],
                check_results: &[check_result],
                rechecks: &[(previous.id.clone(), vec![recheck])],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings.len(), 1);
        assert_eq!(update.findings[0].status, FindingStatus::Resolved);
        assert_eq!(update.resolved.len(), 1);
        assert!(update.kept_open.is_empty());
    }

    #[test]
    fn a_previous_finding_without_passing_rechecks_stays_open() {
        let previous = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let recheck = CheckId::generate();
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: &[],
                check_results: &[],
                rechecks: &[(previous.id.clone(), vec![recheck])],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings.len(), 1);
        assert_eq!(update.findings[0].status, FindingStatus::Open);
        assert!(update.resolved.is_empty());
        assert_eq!(update.kept_open.len(), 1);
    }

    #[test]
    fn a_failed_recheck_keeps_the_finding_open() {
        let previous = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let recheck = CheckId::generate();
        let check_result = CheckResult::fail(
            recheck.clone(),
            "email send check",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            another_fingerprint(),
        );
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: &[],
                check_results: &[check_result],
                rechecks: &[(previous.id.clone(), vec![recheck])],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings.len(), 1);
        assert_eq!(update.findings[0].status, FindingStatus::Open);
        assert!(update.resolved.is_empty());
        assert_eq!(update.kept_open.len(), 1);
    }

    #[test]
    fn all_rechecks_must_pass_to_resolve() {
        let previous = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let first = CheckId::generate();
        let second = CheckId::generate();
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: &[],
                check_results: &[CheckResult::pass(
                    first.clone(),
                    "first",
                    Severity::MustFix,
                    true,
                    EvidenceClass::DeterministicCheck,
                    another_fingerprint(),
                )],
                rechecks: &[(previous.id.clone(), vec![first, second])],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings[0].status, FindingStatus::Open);
        assert!(update.resolved.is_empty());
    }

    #[test]
    fn a_finding_without_rechecks_cannot_be_resolved() {
        let previous = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: &[],
                check_results: &[],
                rechecks: &[],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings[0].status, FindingStatus::Open);
        assert!(update.resolved.is_empty());
    }

    #[test]
    fn resolved_finding_reappears_as_open() {
        let previous = finding_with(
            "Email not sent",
            "src/email/send.rs",
            FindingStatus::Resolved,
        );
        let current = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let update = reconcile(
            LifecycleInputs {
                previous_open: &[],
                current_findings: std::slice::from_ref(&current),
                check_results: &[],
                rechecks: &[],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings.len(), 1);
        assert_eq!(update.findings[0].status, FindingStatus::Open);
        // The resolved previous finding is not in `previous_open`, so it is
        // ignored.
        assert!(!previous.status.needs_attention());
    }

    /// Two spellings, one file, on a volume that folds case: **one finding**,
    /// and the previous run's finding matched rather than carried.
    ///
    /// This was `keys_match_case_insensitively_on_windows`, which asserted one
    /// count under `#[cfg(windows)]` and another under `#[cfg(not(windows))]`:
    /// the rule was compiled in, so only one of the two answers could be run on
    /// any one machine and the case-keeping answer could not be run on the
    /// machine this repository is developed on at all. The rule is now an input,
    /// so both answers are exercised **here, on every platform**, which is the
    /// stronger half of what that test could do. What it still cannot do is say
    /// which answer this machine's volume gives; the test below asks that, and
    /// `paths::volume` pins the answers the two platform classes ship with.
    #[test]
    fn two_spellings_of_one_file_are_one_finding_when_the_volume_folds_them() {
        let previous = finding_with("Email not sent", "src/EMAIL/SEND.rs", FindingStatus::Open);
        let current = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: std::slice::from_ref(&current),
                check_results: &[],
                rechecks: &[],
                planned: &[],
                case: CaseSensitivity::Insensitive,
            },
            another_fingerprint(),
        );

        // One problem, one finding, and it is this run's finding — the previous
        // run's copy of it is not a second entry in the verdict.
        assert_eq!(update.findings.len(), 1);
        assert_eq!(update.findings[0].id, current.id);
        // The previous finding is neither resolved nor lost: it is the same
        // issue, still open, and it is what the count a reader sees is about.
        assert_eq!(update.kept_open.len(), 1);
        assert_eq!(update.kept_open[0].title, previous.title);
        assert_eq!(update.kept_open[0].status, FindingStatus::Open);
        assert!(update.resolved.is_empty());
        // Matched by key, so the entry in `kept_open` is the previous finding
        // itself rather than a fresh copy of it.
        assert_eq!(update.kept_open[0].id, previous.id);
    }

    /// The same two spellings on a volume that keeps case: **two findings**, and
    /// the previous one carried open beside this run's copy of it.
    ///
    /// This is the answer the task's third clause is about, and the defect the
    /// task exists to remove where it is wrong: it is correct on a volume where
    /// the two spellings really are two files, and it was the answer macOS got
    /// because `normalise_path` asked the operating system instead of the volume
    /// (`#[cfg(not(windows))]`) while the volume CI run `35544579833` measured
    /// there folds case.
    #[test]
    fn two_spellings_of_two_files_are_two_findings_when_the_volume_keeps_case() {
        let previous = finding_with("Email not sent", "src/EMAIL/SEND.rs", FindingStatus::Open);
        let current = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: std::slice::from_ref(&current),
                check_results: &[],
                rechecks: &[],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );

        // Both files are named, because both are files here. Sorted rather than
        // in report order: which of the two comes first is not part of this
        // test's subject.
        assert_eq!(update.findings.len(), 2);
        let mut locations: Vec<String> = update
            .findings
            .iter()
            .map(|finding| finding.evidence[0].anchor.location.clone())
            .collect();
        locations.sort();
        assert_eq!(locations, ["src/EMAIL/SEND.rs", "src/email/send.rs"]);
        // The previous finding did not reappear under its own spelling, so it is
        // carried forward by `reconcile`'s last `else` — the same carry as
        // `a_previous_finding_without_passing_rechecks_stays_open` and
        // `a_previous_finding_that_did_not_reappear_is_carried_beside_the_current_ones`
        // — and `clone_for_state` mints this run's id rather than reusing last
        // run's, because a carried finding belongs to this run.
        assert_eq!(update.kept_open.len(), 1);
        assert_eq!(update.kept_open[0].title, previous.title);
        assert_eq!(update.kept_open[0].status, FindingStatus::Open);
        assert_ne!(update.kept_open[0].id, previous.id);
        assert_eq!(
            update.kept_open[0].evidence[0].anchor.location,
            "src/EMAIL/SEND.rs"
        );
        assert!(update.resolved.is_empty());
    }

    /// The rule this machine's volume gives, reaching the verdict.
    ///
    /// The two tests above say what each answer does. This one asks the volume
    /// the suite is running on — a scratch directory under `target/tmp`, the
    /// same volume as the checkout — and asserts that the answer it gives is the
    /// answer the comparison was made with, which is the claim no `cfg` can
    /// carry and no reasoning can supply.
    ///
    /// **The assertion differs by platform, and this is what it is asking that
    /// platform**: what its volume, not its operating system, does with two
    /// spellings of one name — `paths::volume` names the two answers the shipped
    /// volumes of the two platform classes give, and this test is deliberately
    /// written against the *answer that came back* rather than against the
    /// platform's name, so a machine that mounts a volume which is not its
    /// platform's default still runs, and asserts, whichever arm the volume puts
    /// it in.
    ///
    /// **What it does if the probe cannot answer**: it fails. `case_rule_for`
    /// would fall back to `Sensitive` and the case-keeping arm below would then
    /// pass without the volume having been asked anything, which is a test
    /// passing for the wrong reason. `case_rule_of_volume` is called directly so
    /// that the `None` is visible here rather than absorbed.
    #[test]
    fn the_rule_this_machines_volume_gives_is_the_rule_the_comparison_is_made_with() {
        let root = crate::store::scratch_root().join(format!("case-rule-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("a scratch directory");
        std::fs::write(root.join("Send.rs"), b"x").expect("a name with a case to flip");
        let root = root.to_string_lossy();

        let case = crate::paths::case_rule_of_volume(Path::new(root.as_ref())).unwrap_or_else(|| {
            panic!(
                "the volume holding {root} could not be asked, so this test could not say which \
                 answer it was asserting"
            )
        });
        assert_eq!(
            case_rule_for(root.as_ref()),
            case,
            "`case_rule_for` did not carry the answer the volume gave"
        );

        let previous = finding_with("Email not sent", "src/EMAIL/SEND.rs", FindingStatus::Open);
        let current = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: std::slice::from_ref(&current),
                check_results: &[],
                rechecks: &[],
                planned: &[],
                case,
            },
            another_fingerprint(),
        );

        match case {
            CaseSensitivity::Insensitive => {
                assert_eq!(update.findings.len(), 1);
                assert_eq!(update.kept_open[0].id, previous.id);
            }
            CaseSensitivity::Sensitive => {
                assert_eq!(update.findings.len(), 2);
                assert_ne!(update.kept_open[0].id, previous.id);
            }
        }
    }

    /// Two *different* files, not two spellings of one: a previous finding for
    /// one path and a current finding for another.
    ///
    /// This is the shape the case-keeping answer takes: the same carry the
    /// `Sensitive` arm of the volume test above asserts, reached with two paths
    /// that differ by more than case. Written so that it holds on every
    /// platform, which matters because it is the statement the machine this
    /// repository is developed on cannot reach through its own volume. Here the
    /// rule is passed in rather than observed, so that is no longer a limitation
    /// of the test.
    ///
    /// What it pins is that a carry and a fresh finding are two entries and not
    /// one: the previous finding is neither matched nor resolvable, so it is
    /// reported open *and* counted as kept open.
    #[test]
    fn a_previous_finding_that_did_not_reappear_is_carried_beside_the_current_ones() {
        let previous = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let current = finding_with("Email not sent", "src/email/other.rs", FindingStatus::Open);
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: std::slice::from_ref(&current),
                check_results: &[],
                rechecks: &[],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings.len(), 2);
        assert_eq!(update.kept_open.len(), 1);
        assert_eq!(update.kept_open[0].title, previous.title);
        assert_eq!(update.kept_open[0].status, FindingStatus::Open);
        // Not the previous id: a carried finding belongs to this run and gets
        // this run's id. The anchor is what says it is the same issue.
        assert_ne!(update.kept_open[0].id, previous.id);
        assert_eq!(
            update.kept_open[0].evidence[0].anchor.location,
            "src/email/send.rs"
        );
        // And it is reported as well as counted: the verdict a reader sees has
        // it in `findings`, and `kept_open` is what the progress sentence counts.
        assert!(
            update
                .findings
                .iter()
                .any(|f| f.id == update.kept_open[0].id && f.status == FindingStatus::Open)
        );
        assert!(update.resolved.is_empty());
    }

    #[test]
    fn findings_are_sorted_most_severe_first() {
        let note = FindingBuilder::new(
            AssessmentSource::ObservedFact,
            SeverityRationale::Informational,
        )
        .id(FindingId::generate())
        .title("note")
        .severity(Severity::Note)
        .status(FindingStatus::Open)
        .fingerprint(fingerprint())
        .evidence(vec![Evidence::new(
            EvidenceClass::ObservedFact,
            "s",
            EvidenceAnchor::new(AnchorSubject::File, "src/a.rs", "line 1"),
            Some(fingerprint()),
            Severity::Note,
        )])
        .build()
        .unwrap();

        let must_fix = finding_with("must fix", "src/b.rs", FindingStatus::Open);

        let update = reconcile(
            LifecycleInputs {
                previous_open: &[],
                current_findings: &[note.clone(), must_fix.clone()],
                check_results: &[],
                rechecks: &[],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings[0].severity, Severity::MustFix);
        assert_eq!(update.findings[1].severity, Severity::Note);
    }

    #[test]
    fn cannot_confirm_is_carried_forward() {
        let previous = finding_with(
            "Email not sent",
            "src/email/send.rs",
            FindingStatus::CannotConfirm,
        );
        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: &[],
                check_results: &[],
                rechecks: &[],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings[0].status, FindingStatus::Open);
        assert_eq!(update.kept_open.len(), 1);
    }

    #[test]
    fn a_finding_with_no_checkable_anchor_is_carried_open() {
        let previous = FindingBuilder::new(
            AssessmentSource::ModelAssessment,
            SeverityRationale::Informational,
        )
        .id(FindingId::generate())
        .title("model-only uncertainty")
        .severity(Severity::Note)
        .status(FindingStatus::Open)
        .fingerprint(fingerprint())
        .evidence(vec![Evidence::new(
            EvidenceClass::ModelAssessment,
            "inferred",
            EvidenceAnchor::model_only("model-only conclusion"),
            Some(fingerprint()),
            Severity::Note,
        )])
        .build()
        .unwrap();

        let update = reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: &[],
                check_results: &[],
                rechecks: &[],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert_eq!(update.findings.len(), 1);
        assert_eq!(update.findings[0].status, FindingStatus::Open);
        assert_eq!(update.kept_open.len(), 1);
    }

    #[test]
    fn open_after_reconcile_returns_only_attention_needed() {
        let previous = finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open);
        let recheck = CheckId::generate();
        let open = open_after_reconcile(
            LifecycleInputs {
                previous_open: std::slice::from_ref(&previous),
                current_findings: &[],
                check_results: &[CheckResult::pass(
                    recheck.clone(),
                    "email send check",
                    Severity::MustFix,
                    true,
                    EvidenceClass::DeterministicCheck,
                    another_fingerprint(),
                )],
                rechecks: &[(previous.id.clone(), vec![recheck])],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        assert!(open.is_empty());
    }

    /// The read that finds what an earlier run left open is only useful if a run
    /// wrote it down and it reports each finding once.
    ///
    /// # Mutations this test is built to redden
    ///
    /// - `HISTORY_SCAN_LIMIT = 0` — the value this read carried before
    ///   `P7-T012`. `Store::history` documents `0` as "return none", and the
    ///   implementation passes it through to SQLite as `LIMIT 0`, so the read
    ///   answers "no earlier run left anything open" about a store holding two
    ///   runs of three open findings. Both count assertions fail.
    /// - `HISTORY_SCAN_LIMIT = 2` — a small non-zero limit, which is the tempting
    ///   fix and is not one: the query is newest-first, so the scan spends its
    ///   rows on the newest readings and never reaches an earlier run's rows at
    ///   all. The first count assertion fails while the store still holds every
    ///   one of the findings.
    /// - deleting the `seen.insert(key)` guard in [`previous_open_findings`] —
    ///   each run stores every finding, so one unchanged project checked twice
    ///   reports six entries for three problems. Measured on the CLI before the
    ///   guard existed: three runs over one unchanged project, and the third
    ///   said `6 earlier finding(s) stayed open` for three findings.
    #[test]
    fn a_previous_runs_open_findings_are_reported_once_each() {
        let store = store_in("recheck-lifecycle-history");
        let project = "C:/projects/sendmail";
        let fixtures = [
            ("Email not sent", "src/email/send.rs"),
            ("Retry loop never ends", "src/email/retry.rs"),
            ("Timeout is one second", "src/email/config.rs"),
        ];
        let open_in = |fixtures: &[(&str, &str)]| -> Vec<Finding> {
            fixtures
                .iter()
                .map(|(title, location)| finding_with(title, location, FindingStatus::Open))
                .collect()
        };

        // Run one: three open findings.
        store_run(&store, project, &fingerprint(), &open_in(&fixtures), &[])
            .expect("the first run is stored");

        // Run two: the same three findings with freshly minted ids — which is
        // what a second run over unchanged bytes produces, because a finding id
        // is generated per run — and one the run itself resolved.
        let mut second = open_in(&fixtures);
        second.push(finding_with(
            "Closed by the repair",
            "src/email/other.rs",
            FindingStatus::Resolved,
        ));
        store_run(&store, project, &fingerprint(), &second, &[]).expect("the second run is stored");

        let mut open: Vec<String> =
            previous_open_findings(&store, project, CaseSensitivity::Sensitive)
                .expect("the history reads")
                .into_iter()
                .map(|finding| finding.title)
                .collect();
        open.sort();
        assert_eq!(
            open,
            [
                "Email not sent",
                "Retry loop never ends",
                "Timeout is one second"
            ],
            "two runs of three open findings are three findings, and the resolved one is not among them"
        );

        // Another project's finding is not this project's open list, however
        // much of the store it shares.
        store_run(
            &store,
            "C:/projects/other",
            &fingerprint(),
            &[finding_with(
                "Someone else's problem",
                "src/other.rs",
                FindingStatus::Open,
            )],
            &[],
        )
        .expect("the other project's run is stored");
        let mut after: Vec<String> =
            previous_open_findings(&store, project, CaseSensitivity::Sensitive)
                .expect("the history reads")
                .into_iter()
                .map(|finding| finding.title)
                .collect();
        after.sort();
        assert_eq!(
            after, open,
            "another project's findings are not this project's open list"
        );
    }

    /// The other half of the third clause, and the one that reaches the store:
    /// a history that holds both spellings of one file must not hand back two
    /// findings for one problem.
    ///
    /// The `seen` guard above is what does this — a run stores every finding it
    /// produced, so two runs that spelt one path two ways leave two rows in the
    /// store. On a volume that folds case those rows are one finding and the
    /// reader gets one; on a volume that keeps case they are two files and the
    /// reader gets two. **Measured here, both rules, one store: `1` and `2`.**
    ///
    /// What the shipped build did, before this change: its rule was
    /// `trimmed.to_lowercase()` under `#[cfg(windows)]` — the same expression
    /// [`CaseSensitivity::Insensitive`] selects, read from the source rather than
    /// measured — so this read answered one on Windows and two on the Unix
    /// branch, which is the premise `P15-T016` measured on CI. On Windows the
    /// answer is therefore unchanged; what changes is that the answer now comes
    /// from the volume instead of from a platform name, and macOS — whose volume
    /// CI run `35544579833` measured as folding — stops taking the Unix branch's
    /// answer.
    #[test]
    fn a_history_holding_both_spelling_of_one_file_hands_back_one_finding() {
        let store = store_in("recheck-lifecycle-case");
        let project = "C:/projects/sendmail";
        store_run(
            &store,
            project,
            &fingerprint(),
            &[
                finding_with("Email not sent", "src/EMAIL/SEND.rs", FindingStatus::Open),
                finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open),
            ],
            &[],
        )
        .expect("the run is stored");

        let folding = previous_open_findings(&store, project, CaseSensitivity::Insensitive)
            .expect("the history reads");
        assert_eq!(
            folding.len(),
            1,
            "two rows for one file came back as two findings"
        );

        let keeping = previous_open_findings(&store, project, CaseSensitivity::Sensitive)
            .expect("the history reads");
        assert_eq!(
            keeping.len(),
            2,
            "two files' findings were deduplicated into one"
        );
        assert_eq!(keeping[0].title, keeping[1].title);
    }

    /// **The same question, answered the same way as the tier's reader.**
    ///
    /// Which rows are this project's is decided by [`same_project_root`], and
    /// that is only worth anything if it is one rule: a row this filter took as
    /// another project's is a finding the reader was owed, and `capability_report`
    /// asks the identical question about the identical field of the identical
    /// rows when it counts a session's events. Two readers of one store that
    /// answered *when are two paths one project* two ways would let a run be
    /// `(capability tier 1, observed)` for its session and simultaneously owe
    /// nothing it had found open.
    ///
    /// So the two spellings here are the same directory under **every** rule —
    /// a trailing separator and a `.` segment, one of which every platform folds
    /// itself and neither of which is the case question. That is deliberate: a
    /// spelling whose answer depended on the volume would make this test's
    /// assertion a claim about the machine rather than about the filter, and the
    /// case question is already pinned by
    /// `two_spellings_of_one_file_are_one_finding_when_the_volume_folds_them` and
    /// its opposite beside it. The last reading is the direction that must not be
    /// traded: a genuinely different directory is still another project's.
    #[test]
    fn a_run_stored_under_one_spelling_of_the_project_is_this_projects_history() {
        let store = store_in("recheck-lifecycle-project-spelling");
        let recorded = "C:/projects/sendmail";
        store_run(
            &store,
            recorded,
            &fingerprint(),
            &[
                finding_with("Email not sent", "src/email/send.rs", FindingStatus::Open),
                finding_with(
                    "Retry loop never ends",
                    "src/email/retry.rs",
                    FindingStatus::Open,
                ),
            ],
            &[],
        )
        .expect("the run is stored");

        let titles = |project: &str| -> Vec<String> {
            previous_open_findings(&store, project, CaseSensitivity::Sensitive)
                .expect("the history reads")
                .into_iter()
                .map(|finding| finding.title)
                .collect()
        };

        for spelling in [
            "C:/projects/sendmail/",
            "C:/projects/./sendmail",
            "C:/projects/x/../sendmail",
        ] {
            let mut open = titles(spelling);
            open.sort();
            assert_eq!(
                open,
                ["Email not sent", "Retry loop never ends"],
                "{spelling} is {recorded}, so its run's open findings are this project's, \
                 and the reader was handed a history that said otherwise"
            );
        }

        assert!(
            titles("C:/projects/sendmail2").is_empty(),
            "a different directory was handed this project's open findings"
        );
    }

    /// The refusal's own text, which is what a reader is handed.
    ///
    /// This read does not fail into a log line nobody reads: `pipeline::recheck`
    /// puts the error's `Display` into stage 12's detail, so this text is the
    /// sentence a person ends up reading. The two things it must carry are
    /// **which project and which bound** — a reader who cannot tell whether the
    /// bound was about their project has no way to act — and the one thing it must
    /// not carry is the reassuring reading of the same short list.
    ///
    /// The shape asserted is: the project is named, the bound is named, and the
    /// sentence SURE writes when it genuinely found nothing
    /// (`pipeline::recheck`'s `"no earlier run left anything open for this
    /// project."`) is not what a stopped scan says instead.
    #[test]
    fn the_refusal_names_the_project_and_the_bound_and_not_the_reassuring_reading() {
        let store = store_in("recheck-lifecycle-refusal-text");
        let project = "C:/projects/sendmail";
        store_run(
            &store,
            project,
            &fingerprint(),
            &[finding_with(
                "Email not sent",
                "src/email/send.rs",
                FindingStatus::Open,
            )],
            &[],
        )
        .expect("the run is stored");

        let error = previous_open_findings_within(&store, project, CaseSensitivity::Sensitive, 1)
            .expect_err("a scan that read its whole bound did not stop at it");
        assert!(
            matches!(error, HistoryReadError::ScanStoppedEarly { .. }),
            "a bound is not a store failure, and reporting it as one sends a reader \
             looking for a damaged file: {error:?}"
        );
        let text = error.to_string();
        assert!(
            text.contains(project),
            "the message does not name it: {text}"
        );
        assert!(
            text.contains(&1.to_string()),
            "the message does not name the bound it stopped at: {text}"
        );
        assert!(
            !text.contains("no earlier run left anything open"),
            "a scan that stopped early is saying what a scan that found nothing says: {text}"
        );
    }

    /// The bound, driven as a number rather than argued about.
    ///
    /// Three rows, of which **this project's is the oldest** — which is the shape
    /// the defect has: the scan is newest-first, so a bound spent on other
    /// projects' rows is spent before this project's rows are ever looked at.
    ///
    /// The three readings below are what pin the edge. `4` is a bound past the end
    /// of the store, and it answers with the project's finding — so the finding is
    /// there, and a shorter answer is a lost one rather than an empty project.
    /// `3` is exactly the number of rows the store holds: SURE read the whole
    /// store and still refuses, which is the conservative half of `>=` and is
    /// stated in the read's comment rather than left to be discovered. `2` is the
    /// false green itself: the row the reader needs is *outside* what was read, and
    /// before `P15-T029` this call answered `Ok(vec![])`, which reads as "nothing
    /// was left open".
    #[test]
    fn the_bound_refuses_at_the_row_it_reaches_and_answers_one_short_of_it() {
        let store = store_in("recheck-lifecycle-bound-edge");
        let project = "C:/projects/sendmail";
        let other = "C:/projects/other";

        store_run(
            &store,
            project,
            &fingerprint(),
            &[finding_with(
                "Email not sent",
                "src/email/send.rs",
                FindingStatus::Open,
            )],
            &[],
        )
        .expect("this project's run is stored first, so its row is the oldest");
        store_run(
            &store,
            other,
            &fingerprint(),
            &[
                finding_with(
                    "Someone else's problem",
                    "src/other/one.rs",
                    FindingStatus::Open,
                ),
                finding_with(
                    "Someone else's problem",
                    "src/other/two.rs",
                    FindingStatus::Open,
                ),
            ],
            &[],
        )
        .expect("the other project's two runs are stored after it, so they are newer");

        let read = |limit: usize| {
            previous_open_findings_within(&store, project, CaseSensitivity::Sensitive, limit)
        };

        let read_to_the_end = read(4).expect("a bound past the end of the store is not a stop");
        assert_eq!(
            read_to_the_end.len(),
            1,
            "the project's open finding is in the store, beyond the two newer rows"
        );
        assert_eq!(read_to_the_end[0].0.title, "Email not sent");

        for limit in [2, 3] {
            match read(limit) {
                Ok(findings) => panic!(
                    "a scan that stopped at {limit} record(s) answered with {} finding(s); the \
                     project's own open finding was outside what it read, so this list is short \
                     for a reason the caller cannot see",
                    findings.len()
                ),
                Err(HistoryReadError::ScanStoppedEarly { limit: got, .. }) => {
                    assert_eq!(got, limit)
                }
                Err(other) => {
                    panic!("the store was readable and only the bound was reached: {other}")
                }
            }
        }
    }

    /// The number production uses, reached on purpose.
    ///
    /// The test above drives the branch at a size it can afford, which is a
    /// different claim from "the number SURE ships is one that can be reached".
    /// This one fills a store past [`HISTORY_SCAN_LIMIT`] and reads it through
    /// [`previous_open_findings`] — the entry point production calls — so the
    /// constant itself is exercised and an off-by-one in it would be visible here
    /// rather than only in a comment.
    ///
    /// **What it would catch**: a bound that is not checked (`Ok` with 0 findings
    /// in the saturated reading — the defect this task exists for), a check on the
    /// wrong side of the read, and a bound that started refusing one row too early
    /// (the `limit + 2` reading below would then miss the finding it must find).
    #[test]
    fn a_store_past_the_shipped_bound_makes_the_read_refuse_rather_than_answer_zero() {
        let store = store_in("recheck-lifecycle-saturated");
        let project = "C:/projects/sendmail";
        let other = "C:/projects/other";

        // This project's open finding first, so it is the oldest row in the store.
        store_run(
            &store,
            project,
            &fingerprint(),
            &[finding_with(
                "Email not sent",
                "src/email/send.rs",
                FindingStatus::Open,
            )],
            &[],
        )
        .expect("this project's run is stored");

        // Then HISTORY_SCAN_LIMIT rows belonging to another project, all newer.
        // Written through [`store_run`], which is the call the product writes a
        // run's findings with — one row per finding it holds, so this is
        // HISTORY_SCAN_LIMIT rows and the same number of write transactions. What
        // the test needs is the row count, not any particular call count.
        let filler: Vec<Finding> = (0..HISTORY_SCAN_LIMIT)
            .map(|i| {
                finding_with(
                    &format!("Someone else's problem {i}"),
                    &format!("src/other/{i}.rs"),
                    FindingStatus::Open,
                )
            })
            .collect();
        store_run(&store, other, &fingerprint(), &filler, &[]).expect("the filler is stored");

        match previous_open_findings(&store, project, CaseSensitivity::Sensitive) {
            Ok(findings) => panic!(
                "the scan stopped at {HISTORY_SCAN_LIMIT} records, and it answered with {} \
                 finding(s) anyway — the project's own finding is one row past the bound, so a \
                 short list here is the false green this read must not report",
                findings.len()
            ),
            Err(HistoryReadError::ScanStoppedEarly {
                limit,
                project_root,
            }) => {
                assert_eq!(limit, HISTORY_SCAN_LIMIT);
                assert_eq!(project_root, project);
            }
            Err(other) => panic!("the store was readable and only the bound was reached: {other}"),
        }

        // And the finding was genuinely one row beyond it, rather than absent: with
        // room for every row in the store the same read answers with it. Without
        // this, the refusal above would be consistent with a store that had
        // nothing to find.
        let read_to_the_end = previous_open_findings_within(
            &store,
            project,
            CaseSensitivity::Sensitive,
            HISTORY_SCAN_LIMIT + 2,
        )
        .expect("a bound past the end of the store is not a stop");
        assert_eq!(read_to_the_end.len(), 1);
        assert_eq!(read_to_the_end[0].0.title, "Email not sent");
    }

    // ---- What a repair wrote since the earlier run -------------------------

    use crate::harness_event::IngestedEvent;
    use crate::session_event_store::SessionEventStore;
    use sure_domain::ids::EventId;
    use sure_protocol::PROTOCOL_VERSION;
    use sure_protocol::documents::DocumentKind;
    use sure_protocol::event::EventEnvelope;

    /// Store one harness event for `project`, the way a plugin's hook does.
    fn record_event(store: &Store, project: &str, event_type: &str, payload: serde_json::Value) {
        let envelope = EventEnvelope::new("miqi", event_type, "2026-10-28T09:10:56.827Z")
            .with_session_id("session-42")
            .with_project_root(project)
            .with_payload(payload);
        let ingested = IngestedEvent {
            envelope,
            protocol_version: PROTOCOL_VERSION,
            document_kind: DocumentKind::Event,
        };
        SessionEventStore::new(store)
            .persist(&ingested, project, &fingerprint(), &EventId::generate())
            .expect("the event is stored");
    }

    fn write(store: &Store, project: &str, path: &str) {
        record_event(
            store,
            project,
            "file.written",
            serde_json::json!({"path": path, "written": true}),
        );
    }

    /// Store an earlier run with one open finding, read it back the way stage 12
    /// does, and reconcile it against a re-check that now passes.
    ///
    /// The caller records the repair's events after this returns.
    fn earlier_finding_with_a_passing_recheck(
        store: &Store,
        project: &str,
    ) -> (Vec<(Finding, i64)>, LifecycleUpdate) {
        let previous = finding_with("run the Java tests", "pom.xml", FindingStatus::Open);
        store_run(
            store,
            project,
            &fingerprint(),
            std::slice::from_ref(&previous),
            &[],
        )
        .expect("the earlier run is stored");
        let dated = previous_open_findings_with_times(store, project, CaseSensitivity::Sensitive)
            .expect("the earlier findings are read");
        let earlier: Vec<Finding> = dated.iter().map(|(f, _)| f.clone()).collect();
        let recheck = CheckId::generate();
        let update = reconcile(
            LifecycleInputs {
                previous_open: &earlier,
                current_findings: &[],
                check_results: &[CheckResult::pass(
                    recheck.clone(),
                    "run the Java tests",
                    Severity::MustFix,
                    true,
                    EvidenceClass::DeterministicCheck,
                    another_fingerprint(),
                )],
                rechecks: &[(earlier[0].id.clone(), vec![recheck])],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );
        (dated, update)
    }

    /// The measured 2026-10-28 MiQi case: a failing Maven test, a repair that
    /// changed only `AppTest.java`, and a re-check the changed assertion made
    /// pass. The check passing is not enough; the finding stays open because
    /// nothing but the test was changed.
    #[test]
    fn a_check_failure_is_not_closed_by_editing_only_its_test() {
        let store = store_in("recheck-test-only-repair");
        let project = "C:/projects/maven";
        let (dated, update) = earlier_finding_with_a_passing_recheck(&store, project);
        assert_eq!(
            update.resolved.len(),
            1,
            "without the write evidence, a passing check closes the finding"
        );

        write(&store, project, "src/test/java/com/example/AppTest.java");
        let writes = repair_writes_since(&store, project, CaseSensitivity::Sensitive, &dated)
            .expect("the writes are read");
        let (update, reopened) =
            keep_test_only_fixes_open(update, &writes, CaseSensitivity::Sensitive);

        assert_eq!(reopened.len(), 1);
        assert!(update.resolved.is_empty());
        assert_eq!(update.kept_open.len(), 1);
        assert_eq!(update.kept_open[0].title, "run the Java tests");
        assert_eq!(update.findings.len(), 1);
        assert_eq!(update.findings[0].status, FindingStatus::Open);
    }

    /// The control: as soon as one recorded write is not a test file, the check
    /// result is enough again. An accompanying test edit must not hold a real
    /// fix open.
    ///
    /// `src/main/java/com/example/App.java` is deliberately the Maven archetype
    /// path: `classify_path` reads the `example` package directory as example
    /// material, so this test also pins that the guard only fires on a *test*
    /// file and does not claim a production path is a test.
    #[test]
    fn a_recorded_write_outside_the_test_lets_the_check_close_the_finding() {
        let store = store_in("recheck-production-repair");
        let project = "C:/projects/maven";
        let (dated, update) = earlier_finding_with_a_passing_recheck(&store, project);

        write(&store, project, "src/test/java/com/example/AppTest.java");
        write(&store, project, "src/main/java/com/example/App.java");
        let writes = repair_writes_since(&store, project, CaseSensitivity::Sensitive, &dated)
            .expect("the writes are read");
        let (update, reopened) =
            keep_test_only_fixes_open(update, &writes, CaseSensitivity::Sensitive);

        assert!(reopened.is_empty(), "{writes:?}");
        assert_eq!(update.resolved.len(), 1);
        assert!(update.kept_open.is_empty());
    }

    /// A file write recorded before the earlier run wrote its finding down is not
    /// part of any repair: the window opens at the finding's own row.
    #[test]
    fn writes_from_before_the_earlier_run_are_not_part_of_the_repair() {
        let store = store_in("recheck-writes-before");
        let project = "C:/projects/maven";
        write(&store, project, "src/test/java/com/example/AppTest.java");
        std::thread::sleep(std::time::Duration::from_millis(5));

        let (dated, update) = earlier_finding_with_a_passing_recheck(&store, project);
        let writes = repair_writes_since(&store, project, CaseSensitivity::Sensitive, &dated)
            .expect("the writes are read");
        let (update, reopened) =
            keep_test_only_fixes_open(update, &writes, CaseSensitivity::Sensitive);

        assert!(reopened.is_empty());
        assert_eq!(
            update.resolved.len(),
            1,
            "a write made before the finding was stored cannot explain its repair"
        );
    }

    /// Reading a test file is not changing it.
    #[test]
    fn a_recorded_read_is_not_a_repair() {
        let store = store_in("recheck-read-only");
        let project = "C:/projects/maven";
        let (dated, update) = earlier_finding_with_a_passing_recheck(&store, project);

        record_event(
            &store,
            project,
            "file.read",
            serde_json::json!({"path": "src/test/java/com/example/AppTest.java"}),
        );
        let writes = repair_writes_since(&store, project, CaseSensitivity::Sensitive, &dated)
            .expect("the writes are read");
        let (update, reopened) =
            keep_test_only_fixes_open(update, &writes, CaseSensitivity::Sensitive);

        assert!(reopened.is_empty());
        assert_eq!(update.resolved.len(), 1);
    }

    /// Another project's write is not this project's repair, however much of the
    /// store it shares.
    #[test]
    fn an_event_for_another_project_does_not_hold_this_finding_open() {
        let store = store_in("recheck-other-project-write");
        let project = "C:/projects/maven";
        let (dated, update) = earlier_finding_with_a_passing_recheck(&store, project);

        write(
            &store,
            "C:/projects/other",
            "src/test/java/com/example/AppTest.java",
        );
        let writes = repair_writes_since(&store, project, CaseSensitivity::Sensitive, &dated)
            .expect("the writes are read");
        let (update, reopened) =
            keep_test_only_fixes_open(update, &writes, CaseSensitivity::Sensitive);

        assert!(reopened.is_empty());
        assert_eq!(update.resolved.len(), 1);
    }

    /// A scan that reached its bound may be missing the production write, so it
    /// must not be read as proof that no product file changed.
    #[test]
    fn a_scan_that_stops_at_its_bound_does_not_rule_out_a_production_write() {
        let store = store_in("recheck-write-scan-bound");
        let project = "C:/projects/maven";
        let (dated, update) = earlier_finding_with_a_passing_recheck(&store, project);
        write(&store, project, "src/test/java/com/example/AppTest.java");

        let writes =
            repair_writes_since_within(&store, project, CaseSensitivity::Sensitive, &dated, 1)
                .expect("the read answers");
        let entry = writes
            .get(&FindingKey::from_finding(&dated[0].0, CaseSensitivity::Sensitive).expect("key"))
            .expect("the finding is in the map");
        assert!(
            !entry.complete,
            "a scan that stopped at its bound is incomplete"
        );

        let (update, reopened) =
            keep_test_only_fixes_open(update, &writes, CaseSensitivity::Sensitive);
        assert!(reopened.is_empty());
        assert_eq!(update.resolved.len(), 1);
    }

    /// A finding whose strongest evidence is not a deterministic check does not
    /// carry the "do not change the test" clause, and the guard must not invent
    /// one for it.
    #[test]
    fn a_finding_that_is_not_a_check_failure_is_not_held_open_this_way() {
        let store = store_in("recheck-observed-fact");
        let project = "C:/projects/maven";
        let mut previous = finding_with("run the Java tests", "pom.xml", FindingStatus::Open);
        previous.evidence[0].class = EvidenceClass::ObservedFact;
        store_run(
            &store,
            project,
            &fingerprint(),
            std::slice::from_ref(&previous),
            &[],
        )
        .expect("the earlier run is stored");
        let dated = previous_open_findings_with_times(&store, project, CaseSensitivity::Sensitive)
            .expect("the earlier findings are read");
        let earlier: Vec<Finding> = dated.iter().map(|(f, _)| f.clone()).collect();
        let recheck = CheckId::generate();
        let update = reconcile(
            LifecycleInputs {
                previous_open: &earlier,
                current_findings: &[],
                check_results: &[CheckResult::pass(
                    recheck.clone(),
                    "run the Java tests",
                    Severity::MustFix,
                    true,
                    EvidenceClass::ObservedFact,
                    another_fingerprint(),
                )],
                rechecks: &[(earlier[0].id.clone(), vec![recheck])],
                planned: &[],
                case: CaseSensitivity::Sensitive,
            },
            another_fingerprint(),
        );

        write(&store, project, "src/test/java/com/example/AppTest.java");
        let writes = repair_writes_since(&store, project, CaseSensitivity::Sensitive, &dated)
            .expect("the writes are read");
        let (update, reopened) =
            keep_test_only_fixes_open(update, &writes, CaseSensitivity::Sensitive);

        assert!(reopened.is_empty());
        assert_eq!(update.resolved.len(), 1);
    }

    /// The regression the 2026-10-28 MiQi repair-loop retest found: a pytest
    /// test at the project root is `test_totals.py`, which `classify_path` reads
    /// as product. The guard has to recognise it or "edited only the test"
    /// closes the finding.
    #[test]
    fn a_root_level_pytest_test_file_counts_as_the_test() {
        let store = store_in("recheck-pytest-style");
        let project = "C:/projects/pyt";
        let (dated, update) = earlier_finding_with_a_passing_recheck(&store, project);
        write(&store, project, "test_totals.py");
        let writes = repair_writes_since(&store, project, CaseSensitivity::Sensitive, &dated)
            .expect("the writes are read");
        let (update, reopened) =
            keep_test_only_fixes_open(update, &writes, CaseSensitivity::Sensitive);

        assert_eq!(reopened.len(), 1);
        assert!(update.resolved.is_empty());
        assert_eq!(update.kept_open.len(), 1);
    }

    /// `classify_path`'s own rule stays the stricter one — a helper named
    /// `test_…` in product code is not a production finding's context — but for
    /// the guard the safe direction is wider: a test helper edited alone is
    /// still not the behaviour the check was about, so it counts as test code.
    #[test]
    fn a_file_is_a_test_by_its_name_only_when_the_whole_stem_says_so() {
        for test in [
            "test_totals.py",
            "totals_test.py",
            "tests/test_totals.py",
            "test/check.js",
            "foo.test.ts",
            "foo.spec.ts",
            "test-utils.js",
            "conftest.py",
            "tests.rs",
            "src/test_helper.rs",
        ] {
            assert!(is_test_file(test), "{test} is a test file");
        }
        for product in [
            "src/main.rs",
            "testing.py",
            "contest.py",
            "latest.py",
            "pom.xml",
        ] {
            assert!(!is_test_file(product), "{product} is not a test file");
        }
    }

    /// The path arithmetic the read depends on: harness text, both separators,
    /// and the project root's own spelling.
    #[test]
    fn a_recorded_path_is_placed_against_the_project_root() {
        let case = CaseSensitivity::Sensitive;
        assert_eq!(
            relative_to_project(
                r"D:\Code\maven\src\test\java\AppTest.java",
                "D:/Code/maven",
                case
            ),
            Some(String::from("src/test/java/AppTest.java"))
        );
        assert_eq!(
            relative_to_project("./src/main/java/App.java", "D:/Code/maven", case),
            Some(String::from("src/main/java/App.java"))
        );
        assert_eq!(
            relative_to_project("/home/me/maven/src/x.py", "/home/me/maven", case),
            Some(String::from("src/x.py"))
        );
        assert_eq!(
            relative_to_project("D:/Somewhere/else/x.rs", "D:/Code/maven", case),
            None,
            "another project's path is not this project's file"
        );
        assert_eq!(
            relative_to_project("../outside/x.rs", "D:/Code/maven", case),
            None,
            "a path that climbs out of the project is outside it"
        );
        assert_eq!(
            relative_to_project("D:/Code/maven", "D:/Code/maven", case),
            None,
            "the project root is not a file inside it"
        );
        assert_eq!(
            relative_to_project("d:/code/maven/src/x.rs", "D:/Code/maven", case),
            None,
            "on a volume that keeps case, the folder's spelling is part of the path; \
             only the drive letter is always compared without case"
        );
        assert_eq!(
            relative_to_project(
                "d:/code/maven/src/x.rs",
                "D:/Code/maven",
                CaseSensitivity::Insensitive
            ),
            Some(String::from("src/x.rs"))
        );
    }
}
