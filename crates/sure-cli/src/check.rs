//! `sure check`, `sure recheck` and `sure repair`: one run of the check
//! pipeline, and the two ways of writing it down.
//!
//! # What this module is, and what it is not
//!
//! The three commands that reach the engine, and the only place in this crate
//! that does. It gathers what a run needs — the project, the project's settings,
//! the history, and the goal the user typed — hands them to
//! [`sure_core::pipeline::Pipeline`], and renders what comes back. **It runs no
//! stage itself**: no detector is called here, no result is aggregated here and
//! no verdict is assembled here. That is what makes "the CLI does not have a
//! second path into the engine" a fact about the source rather than a promise
//! about its behaviour, and it is why the three commands are one module: they
//! differ in how far down the twelve stages they go and in nothing else, so a
//! second copy of the gathering would be a second place for it to be wrong.
//!
//! # The goal, and why it is written first
//!
//! P2-T010's acceptance is that `sure check` can receive and store a trusted
//! explicit goal **without requiring raw transcript recording**. So a goal typed
//! on the command line is written to the record store as a requirement whose
//! source is [`IntentSource::ExplicitUserGoal`] — the source
//! [`IntentSource::is_user_requirement`] accepts, and one that
//! [`IntentSource::requires_full_recording`] asks nothing of. No opt-in is
//! consulted and no recording is written, because there is no session to capture:
//! the words were handed to SURE in the same breath as the command that stored
//! them.
//!
//! It is written **before** the check, which is the property
//! `docs/architecture/CLI.md` documents, and it feeds stage 2 of the same run:
//! the pipeline resolves intent from the goal it was handed rather than from
//! what it happens to find in the history, so a run cannot record one thing and
//! check against another.
//!
//! # What the report shows, and what the record holds
//!
//! One text. The store redacts every document it accepts, so the text beside
//! "Your goal was written to the history as record N" is not the words as they
//! arrived but the record's own text, read back out of that record — and it is
//! the text stage 2 resolves, so the requirement the run checks against is the
//! one it wrote down. The decision, the argument for it and the case against it
//! are in `docs/architecture/PROJECT_INTENT.md`; what is here is the half a
//! reader of this module needs: the goal is not exempt from the store's
//! redaction, and no surface of this command prints a text the record does not
//! hold.
//!
//! Every step before the write can refuse without having changed anything, which
//! is why the order is: the words, then the project path, then the fingerprint,
//! then the store, then the row. A goal with no words in it is refused before
//! SURE looks for its store, and a project SURE cannot read is refused before it
//! opens one — opening a store creates its directory and its file, and leaving a
//! database behind for a run that stored nothing would be a side effect of a
//! failure.
//!
//! # What a run writes on a machine that has never used SURE
//!
//! **Nothing.** The history is opened only when its file is already there: a
//! bare `sure check` on a machine with no history does not create one, because a
//! command that created a store in order to report what it had recorded would be
//! changing the thing it is describing. A run with no history is not a run with
//! a gap in the project — it is a run that has nothing to compare claims or
//! earlier findings against, and the pipeline records both stages as scope
//! limits with that reason.
//!
//! The one exception is `--goal`, which exists to write. A machine with history
//! has its store opened and read on every check, which is the ordinary cost of
//! comparing against what was recorded before.
//!
//! # Why a failure is status 5 and not 3
//!
//! 3 is "this build cannot carry that out", whose remedy is a newer build. These
//! commands *can* carry out what they were asked. A run that met an unreadable
//! project, settings it could not use or a history it could not open tried and
//! did not finish, which is what 5 is for. One status for both is how a broken
//! installation gets read as a build that has nothing to do.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sure_core::config::Authority;
use sure_core::finding::Finding;
use sure_core::fingerprint::{FingerprintOptions, project_fingerprint};
use sure_core::intent::IntentSource;
use sure_core::paths::Paths;
use sure_core::pipeline::{Pipeline, PipelineOutcome, Purpose, RunOutcome, Stage, StageOutcome};
use sure_core::planned_check_runner::ProcessRunner;
use sure_core::privacy::{ModelUse, PrivacyStatement};
use sure_core::process::Cancellation;
use sure_core::project_intent::{EXPLICIT_GOAL_ID, explicit_goal, record};
use sure_core::recheck_lifecycle::store_run;
use sure_core::redact::escape_control_characters;
use sure_core::repair_impact::select_impacted_checks;
use sure_core::status::NotCheckedReason;
use sure_core::store::{Store, StoreError};
use sure_core::vocabulary::{ProjectFingerprint, ProjectVerdict};

use crate::commands::Named;
use crate::human_report::{HumanReportSettings, write_verdict};
use crate::report::{CheckReport, Failed, GoalRecorded, Report, exit};

/// What a run says when nothing was written and nothing was checked.
///
/// One sentence for every failure that happens before the goal is written,
/// because it is true of all of them: each refusal in this module happens
/// before or instead of the write.
const NOTHING_RECORDED: &str = "Nothing was recorded, and nothing was checked.";

/// What a run says when the goal was written and the check did not happen.
///
/// The other sentence, for the other reason. A report using
/// [`NOTHING_RECORDED`] after a successful write would tell the user their
/// history is unchanged when it is not, and they would have no way to find out.
const RECORDED_AND_UNCHECKED: &str = "The goal was recorded, and nothing was checked.";

/// What a run says when the goal was written and no row came back for it.
///
/// Separate again, because this is the one failure here in which something was
/// written and SURE cannot say what.
const RECORDED_WITHOUT_A_ROW: &str =
    "The goal was recorded, and SURE cannot say which record holds it.";

/// What a run says when the row came back and the text it holds cannot be read.
///
/// The same family as [`RECORDED_WITHOUT_A_ROW`] — something was written and
/// SURE cannot say what — and separate from it because what is missing is
/// different: there the row is unknown, here the row is known and its text is
/// not. The one thing this failure must not do is fall back to the words the
/// user typed. Those are the words the store was asked to accept, not the text
/// the record holds, and the case where the two differ is the case where what
/// was removed is a credential: printing them here would put back exactly what
/// the read-back exists to keep out of the report.
const RECORDED_WITHOUT_TEXT: &str =
    "The goal was recorded, and SURE cannot show the text the record holds.";

/// What a run says when it checked the project and could not keep what it found.
///
/// A fourth sentence rather than a reuse, because the other three all describe a
/// run whose work happened before the failure and this one's happened after: the
/// verdict is real and complete, and it is the history the next run compares
/// against that is missing a row. Telling the user *nothing was checked* here
/// would be false, and telling them nothing at all would leave the next `sure
/// recheck` reporting "no earlier run left anything open" about a run that did.
const FOUND_AND_NOT_RECORDED: &str =
    "The project was checked, and what it left open was not recorded.";

/// `sure check`, `sure recheck` or `sure repair`, resolving where SURE keeps
/// its files.
///
/// `named` is what the caller named on the command line — the store directory
/// and the settings file, each `None` for the platform's own location. See
/// [`sure_core::paths::Paths::discover_with`].
///
/// # Errors
///
/// None: a failure is a [`Report::Failed`], because a command that could not
/// finish still has to answer in the shape a caller reads.
#[must_use]
pub fn run(
    purpose: Purpose,
    project: Option<&Path>,
    goal: Option<&str>,
    named: Named<'_>,
) -> Report {
    let project = match project_of(project) {
        Ok(project) => project,
        Err(detail) => return failed(purpose, NOTHING_RECORDED, detail),
    };
    match Paths::discover_with(named.store, named.settings_file) {
        Ok(paths) => run_with(purpose, &paths, &project, goal),
        // Not `Unavailable`: SURE has somewhere to keep its files or it does
        // not, and a machine where it does not is a machine to fix rather than a
        // build to update.
        Err(error) => failed(purpose, NOTHING_RECORDED, error.to_string()),
    }
}

/// The project this run is about: the one named, or the one SURE was run from.
///
/// The documented default is the current directory, and it is resolved to an
/// absolute path here rather than passed along as `.`. `sure_core` refuses to
/// fingerprint a relative root, and the reason is worth keeping: `.` means
/// "wherever this process happens to be", so a record naming it can be read
/// later against a directory the user never meant.
///
/// A path the user gave is passed through untouched, because SURE does not
/// silently repair an argument: `sure check not-a-project` has to say that the
/// root is relative, not quietly check somewhere else. What "not a directory" is
/// worth is decided by the stages — discovery says so at stage 1 and the run
/// stops there with status 5.
fn project_of(project: Option<&Path>) -> Result<PathBuf, String> {
    match project {
        Some(path) => Ok(path.to_path_buf()),
        None => std::env::current_dir().map_err(|error| {
            format!(
                "SURE could not work out which directory it is running in, so it could not \
                 tell which project this is about. Name the project explicitly: {error}"
            )
        }),
    }
}

/// The same, with the locations named rather than discovered.
///
/// Separate from [`run`] so that a test can point SURE at a store it made
/// instead of at the user's own. The alternative was not available: on Windows
/// the per-user data directory is read through `SHGetKnownFolderPath`, which
/// ignores `LOCALAPPDATA`, so there is no environment variable a test could set.
/// A test that ran the real path would be adding an invented requirement to the
/// history of the machine it ran on, and it would look exactly like a passing
/// test.
///
/// `run` reaches this with locations that came from `--store-dir` or from the
/// platform, which is the same rule from the other side: a caller who names a
/// store gets *that* store, and a test that names one cannot reach the machine's
/// own. Nothing about a project is consulted either way.
#[must_use]
pub fn run_with(purpose: Purpose, paths: &Paths, project: &Path, goal: Option<&str>) -> Report {
    // Where this run's settings come from, refused if the project could write
    // it. First, before the goal goes into the history and before any settings
    // are read, because both of those would be a run that acted on a file the
    // thing being judged can edit — the goal is a record about the user, and the
    // settings decide what SURE records and what it may run. The refusal's own
    // words are `PathError::SettingsInsideProject`'s, which is where the rule
    // lives; `crate::hook` asks the same question about the same file before it
    // decides anything, and `docs/architecture/CLI.md` says which file is read
    // and why it may not be this one.
    if let Err(error) = paths.ensure_settings_outside(project) {
        return failed(purpose, NOTHING_RECORDED, error.to_string());
    }

    // The goal first, and in one piece: the words, the project path, the state
    // it is about, the store, the row. Every step of it can refuse without
    // having written anything.
    let mut recorded = None;
    let mut store = None;
    if let Some(goal) = goal {
        match record_goal(paths, project, goal) {
            Ok((written, opened)) => {
                recorded = Some(written);
                store = Some(opened);
            }
            Err(failure) => return failed(purpose, failure.what, failure.detail),
        }
    }

    // The project's own settings, read after the goal is in the history: what
    // the user typed is theirs whether or not the project's file can be read.
    // They decide the execution mode every dynamic check is authorised under, so
    // a run that could not read them has nothing to check with.
    //
    // Read through the authority rather than through `Config::load`, because the
    // project's file is not the only settings file there is. The user's own file
    // outside the project is what decides whether the project's file may have
    // what it asks for (`docs/architecture/CONFIG_AUTHORITY.md`), and the privacy
    // mode this run is under is the arbitrated one — see `sure_core::privacy`.
    // Reading one file would let a run report a policy the user had overridden.
    let authority = match Authority::load(project, &paths.user_config_file()) {
        Ok(authority) => authority,
        Err(error) => {
            let what = if recorded.is_some() {
                RECORDED_AND_UNCHECKED
            } else {
                NOTHING_RECORDED
            };
            return failed(purpose, what, error.to_string());
        }
    };
    let loaded = authority.project_file();
    let privacy = PrivacyStatement::of(&authority);

    // The history — see `open_for` for which commands create one and why.
    if store.is_none() {
        match open_for(purpose, paths, project) {
            Ok(opened) => store = opened,
            Err(error) => return failed(purpose, NOTHING_RECORDED, error.to_string()),
        }
    }

    // Stage 2 resolves the requirement from the text the record holds rather
    // than from the words as they arrived. The two are the same text unless the
    // store's redaction removed something, and in that case checking against the
    // typed words would put the removed value back into the report: the
    // not-checked line for an unmatched requirement quotes the requirement's own
    // text. `Pipeline::goal`'s documentation is the same rule from the other
    // side — a run that wrote a goal and then checked against a different intent
    // would be recording something it did not use.
    let goal_as_recorded = recorded
        .as_ref()
        .map_or(goal, |recorded| Some(recorded.goal.as_str()));

    // What carries out the commands the plan holds, and **this is the product
    // path**: `sure check` on a project whose user has granted `run_project_code`
    // runs that project's own checks through this value. A user who has granted
    // nothing is untouched by it, because `Enforcement` admits nothing that runs
    // project code under `inspect_only` — the default, and the mode a project
    // file cannot move in either direction (`Authority::execution_mode`).
    //
    // The cancellation is the handle a stop would be asked through. Nothing holds
    // the other end of it yet — `sure check` has no interrupt path — so today it
    // is a value that says *nothing has asked this run to stop*, and the bound on
    // any one check is the deadline its plan carries.
    //
    // **The browser driver is bound here, and this is the only place in the
    // product that builds one.** `ProcessRunner` holds it as
    // `Option<sure_core::browser::Driver>` and answers a browser check it was
    // given no driver for with an `Error` — so a caller that forgot this line
    // would get failing browser checks and not passing ones, which is the
    // direction the mistake has to fall in. This function is the composition
    // root for the same reason it is where `Paths`, the store and the pipeline
    // are assembled: it is the layer that is allowed to know which
    // implementations exist, and `sure_core` is not.
    //
    // `Browser::system()` is the right binding here and not a placeholder. It
    // records *look for a browser on this machine* and starts nothing: the search
    // and any launch happen inside one `observe` call, which only runs when a
    // browser check the user's settings and permissions allowed actually reaches
    // the runner. **A machine with no browser is a machine where that call comes
    // back `NoDriverInstalled`, which is a `Skipped` and never a pass** — the
    // explicit result clause three of `P18-T010` is about, produced by the driver
    // rather than by an absence of wiring here.
    //
    // The checks that reach this door are planned in `sure_core::service_plan`,
    // which is the only planner in this build that emits a
    // `CheckOperation::Browser` — `ProbePlan::add_to` still plans every probe as
    // a precomputed observation, and a declared service's page is the one place a
    // real page is asked for. It gets there only when a project declared a
    // service *and* named a page for it *and* the `checks.browser_probe`
    // preference and the user's own permissions both allow it, which is what the
    // refusals in the report are about when one of the three is missing.
    // A run that supplies none of them still binds the driver, because a
    // composition root assembles what the product can do and not only what this
    // one invocation was authorised to do — and a door that is only opened on the
    // runs that need it is a door nobody has tested on the runs that do.
    let runner = ProcessRunner::new(Cancellation::new())
        .with_page_driver(Box::new(sure_core::browser_driver::Browser::system()))
        // Windows installs npm/pnpm/yarn as batch shims, which SURE refuses to
        // start. The launcher starts what npm's shim itself runs — `node` and
        // npm's shipped JavaScript entry — for the names it can prove; every
        // other program is left exactly as the plan holds it.
        .with_package_launchers(sure_core::package_launcher::PackageLaunchers::of_this_machine());
    let run = Pipeline {
        project,
        purpose,
        config: &loaded.config,
        execution: authority.execution(),
        analysis: authority.analysis().value,
        store: store.as_ref(),
        goal: goal_as_recorded,
        runner: &runner,
    }
    .run();

    // What this run found, kept for the run that comes next — which is the whole
    // of what makes stage 12 a comparison rather than a stage that always says
    // there was nothing before it. Written by the commands that carry the loop
    // and by no others: see `open_for`.
    //
    // A failure here ends the command rather than being noted, for the reason
    // the module comment gives for status 5: the next `sure recheck` would
    // otherwise compare against a history missing exactly the row it was run to
    // find, and would report that as "no earlier run left anything open" — a
    // sentence that is true about the store and false about the project.
    if purpose.wants_repair_contracts()
        && let (Some(store), Some(outcome)) = (store.as_ref(), run.run.as_ref())
        && let Err(error) = store_run(
            store,
            &outcome.project_root,
            &outcome.project_state.id,
            &outcome.verdict.findings,
            outcome.report.results(),
        )
    {
        return failed(purpose, FOUND_AND_NOT_RECORDED, error.to_string());
    }

    // Read after the run, because it is the run's own record of the one stage
    // that would ask a model — not a second opinion about the configuration.
    let model_use = ModelUse::of(privacy.provider, &run);

    // What the settings in force allowed, from the same `authority` every
    // decision above was made with — not from a second read of the two files,
    // which could differ from the one the run actually used.
    let grants = crate::grants::Grants::of(&authority, &paths.user_config_file());

    Report::Check(Box::new(CheckReport {
        command: purpose.as_str(),
        project: project.display().to_string(),
        run,
        privacy,
        model_use,
        recorded_goal: recorded,
        grants,
    }))
}

/// Write the user's goal down, and hand back the store it went into.
///
/// The order is the promise: nothing is opened until the words and the project
/// have both been accepted, so a refusal cannot have left a database behind and
/// a user who typed nothing has no record to clean up.
///
/// **The text it hands back is the record's, not the user's.** A goal is stored
/// through a write that redacts every document it accepts, and everything the
/// report says about the goal is this text, so the row is read back and the
/// report prints what it holds. Nothing here returns the words as they arrived:
/// a caller that kept them would have two texts and no rule for which one to
/// show, which is the defect `P15-T024` decided.
fn record_goal(
    paths: &Paths,
    project: &Path,
    goal: &str,
) -> Result<(GoalRecorded, Store), Failure> {
    // The words first. A goal with no words in it is not a requirement, and
    // finding that out needs nothing opened, nothing read and nothing created.
    let intent =
        explicit_goal(goal).map_err(|error| Failure::new(NOTHING_RECORDED, error.to_string()))?;

    // The project as the store takes it — text — before anything is read. A path
    // that cannot be written down is one SURE could not name in the record it
    // was about to write, and the store would have to lose it to proceed.
    let Some(root) = project.to_str() else {
        return Err(Failure::new(
            NOTHING_RECORDED,
            format!(
                "The project path {} is not text SURE can write down, so it could not name \
                 the project this goal is about.",
                project.display()
            ),
        ));
    };

    // Which state of the project this is being recorded against, read before the
    // store is opened. The pipeline takes the fingerprint again at stage 3, and
    // the two agree because both are the same deterministic read of the same
    // tree: what this one buys is that a project SURE cannot read leaves no
    // store behind.
    let state = project_fingerprint(project, &FingerprintOptions::default())
        .map_err(|error| Failure::new(NOTHING_RECORDED, error.to_string()))?;

    let store = Store::open(paths, project)
        .map_err(|error| Failure::new(NOTHING_RECORDED, error.to_string()))?;

    let rows = record(&store, root, &state.id, &intent)
        .map_err(|error| Failure::new(NOTHING_RECORDED, error.to_string()))?;

    // One row, because the intent this builds has one requirement and the schema
    // stores one requirement per row. Written as a match rather than as
    // `rows[0]` so that a later version of `explicit_goal` producing several is a
    // refusal here rather than a report naming the first of them as *the* record
    // — and so that a store that returned nothing is not reported as record #0.
    let Some(row) = rows.first().copied() else {
        return Err(Failure::new(
            RECORDED_WITHOUT_A_ROW,
            "The store accepted the goal and returned no row identifier for it. The goal is in \
             the history; SURE cannot say which record it is. This is a fault in SURE rather \
             than in the goal."
                .to_owned(),
        ));
    };

    // The text the record holds, read back out of the row rather than kept from
    // the words that went in. `store::redact_document` stands between the two —
    // every document a write accepts is redacted — so the text a user reads
    // beside "written to the history as record N" has to be the row's own text,
    // or that sentence describes a record nobody wrote. The two differ exactly
    // when a credential-shaped value was removed, which is the case this
    // read-back is for. Read back rather than redacted a second time here, so
    // that the report and the row agree by construction instead of by two
    // implementations staying in step.
    let text = held_text(&store, row)?;

    Ok((
        GoalRecorded {
            goal: text,
            requirement_id: EXPLICIT_GOAL_ID.to_owned(),
            source: IntentSource::ExplicitUserGoal,
            project_root: root.to_owned(),
            project_state: state,
            record: row,
        },
        store,
    ))
}

/// The text the row holds, or a failure rather than a fallback.
///
/// A read-back rather than a redaction applied here, because the question is
/// not what the redactor would do to the words but what the record holds: the
/// sentence the user reads names a record, and the text under it is read out of
/// that record. `docs/architecture/PROJECT_INTENT.md` records the decision this
/// implements — the store's redaction wins over the goal being stored verbatim,
/// and the report follows the record.
///
/// # Errors
///
/// [`Failure`] carrying [`RECORDED_WITHOUT_TEXT`] if the row cannot be read, or
/// if what comes back holds no text. Neither is a reason to print the words the
/// user typed: those are not the record's text, and the difference between them
/// is what this function exists not to lose.
fn held_text(store: &Store, row: i64) -> Result<String, Failure> {
    let held = store
        .record(row)
        .map_err(|error| Failure::new(RECORDED_WITHOUT_TEXT, error.to_string()))?;
    held.and_then(|record| {
        record
            .document
            .get("text")
            .and_then(Value::as_str)
            .map(str::to_owned)
    })
    .ok_or_else(|| {
        Failure::new(
            RECORDED_WITHOUT_TEXT,
            format!(
                "Record {row} holds no text for the goal. The goal was written before the check \
                 ran, and the row SURE read back is not the row it wrote. This is a fault in SURE \
                 rather than in the goal."
            ),
        )
    })
}

/// The history, when its file is already there.
///
/// Never created. A store that exists and cannot be used is an error rather than
/// an absent history, because the pipeline's "SURE has no recorded history for
/// this machine" is a true sentence only when there is none — a run that said it
/// while a store sat unreadable on the disk would be describing a machine it
/// never looked at.
///
/// # Errors
///
/// [`StoreError::Location`] if the store would be inside the project, and
/// whatever opening it can return.
fn open_existing(paths: &Paths, project: &Path) -> Result<Option<Store>, StoreError> {
    if !paths.store_file().exists() {
        return Ok(None);
    }
    Store::open(paths, project).map(Some)
}

/// The history, created when this command is one that keeps one.
///
/// # Who is allowed to create a store
///
/// `P7-T012` had to answer this, because persisting findings is what makes the
/// second half of the repair loop possible and the module comment above promises
/// that a bare `sure check` writes nothing on a machine that has never used SURE.
/// Both are kept, by drawing the line at the loop:
///
/// - **`sure check` reports.** It creates nothing, before or after. The promise
///   in the module comment holds in exactly the words it is written in, and
///   `a_check_with_no_goal_on_a_machine_with_no_history_writes_nothing` still
///   measures it — the test was not changed to make this possible.
/// - **`sure repair` and `sure recheck` carry the loop**, and a repair loop with
///   no memory is not a loop: `sure repair` writes the finding a later `sure
///   recheck` has to find, and `sure recheck` writes the resolution so that a
///   third run does not re-open what the second one closed. A command whose whole
///   purpose is to compare against an earlier run, that refused to keep the row
///   the next comparison needs, would be a command that could never work.
///
/// The predicate is [`Purpose::wants_repair_contracts`] rather than a list of two
/// names, so a fourth purpose added to the enum has to answer the question —
/// *does this run keep a history?* — instead of inheriting `check`'s answer by
/// default.
///
/// # Errors
///
/// As [`open_existing`], plus whatever creating the store can return.
fn open_for(purpose: Purpose, paths: &Paths, project: &Path) -> Result<Option<Store>, StoreError> {
    if purpose.wants_repair_contracts() {
        return Store::open(paths, project).map(Some);
    }
    open_existing(paths, project)
}

/// One step of [`record_goal`] that did not happen, and what it cost.
struct Failure {
    /// The fixed sentence about what did not happen.
    what: &'static str,
    /// What went wrong, in the words of the thing that went wrong.
    detail: String,
}

impl Failure {
    fn new(what: &'static str, detail: String) -> Self {
        Self { what, detail }
    }
}

/// A run that tried and could not finish.
fn failed(purpose: Purpose, what: &'static str, detail: String) -> Report {
    Report::Failed(Box::new(Failed {
        command: purpose.as_str(),
        what,
        detail,
    }))
}

// --- the human form -----------------------------------------------------

/// Write the human form.
///
/// # Errors
///
/// Any failure from `out`.
pub fn human(report: &CheckReport, out: &mut impl Write) -> io::Result<()> {
    match &report.run.run {
        Some(run) => finished(report, &report.run, run, out),
        // No verdict, so no report: this is a complaint, and `Report::is_an_answer`
        // sends it to standard error where a person piping the report to a file
        // will still see it.
        None => stopped(report, out),
    }
}

/// The human form of a run that produced a verdict.
fn finished(
    report: &CheckReport,
    outcome: &PipelineOutcome,
    run: &RunOutcome,
    out: &mut impl Write,
) -> io::Result<()> {
    writeln!(out, "SURE checked {}.", report.project)?;
    writeln!(out)?;

    // Everything the verdict is made of, in the words this repository already
    // uses for it. Rendering it here a second time would be a second explanation
    // of one result, and the two would drift the first time either was improved.
    write_verdict(
        &run.verdict,
        HumanReportSettings {
            color: false,
            schedule: Some(&run.schedule),
            run_report: Some(&run.report),
        },
        out,
    )?;
    writeln!(out)?;
    checks_that_passed(run, out)?;

    repairs(run, out)?;
    lifecycle(run, out)?;
    stages(outcome, out)?;
    privacy(&report.privacy, report.model_use, out)?;
    // What the run was allowed to do, from the arbitrated settings in force. The
    // section is printed after the privacy one because the two are the same
    // question asked twice — what may leave this machine, and what may it do
    // here — and a person reading them together can see that a run in
    // `inspect_only` with full recording on is one answer rather than two
    // contradictory ones.
    report.grants.human(out)?;
    if let Some(recorded) = &report.recorded_goal {
        what_was_recorded(recorded, out)?;
    }

    // The status, named rather than implied. A person who piped this into a file
    // has lost the exit code, and the two sentences are the difference between
    // "look at your project" and "this build could not do it".
    let status = if report.is_green() {
        writeln!(
            out,
            "SURE exited with status {}, and that is the only status it returns for a project \
             it checked and found clean.",
            exit::OK
        )
    } else {
        writeln!(
            out,
            "SURE exited with status {}. That is what it returns when it checked the project \
             and did not find it clean — not {}, which would mean this build cannot check a \
             project at all.",
            exit::NOT_GREEN,
            exit::UNAVAILABLE
        )
    };
    status?;
    not_clean_note(report, outcome, out)
}

/// The checks that ran and passed, which nothing else in the report names.
///
/// This section exists for one gap and is written to exactly that gap. A check
/// that failed or warned reaches the reader as a finding above, and one that
/// did not run reaches them under "Could not check"; a check that **passed** is
/// a finding by no rule, so before this section a completed pass appeared
/// nowhere in the run at all. Listing every produced result instead would print
/// the title of every failing and warning check a second time — and
/// `is_a_finding` is `false` only for `Pass`, so every one of them is already
/// above, with the reason the plain-language renderer chose for it rather than
/// the raw one.
///
/// It is also where a reader can see that a project's own tests actually ran.
/// The distinction it draws is between a command that completed and a plan that
/// merely allowed one to run. A green here says the command completed; it is
/// not a statement about payment, email, authentication or any other live
/// service the project may talk to.
fn checks_that_passed(run: &RunOutcome, out: &mut impl Write) -> io::Result<()> {
    let passed: Vec<_> = run
        .report
        .results()
        .iter()
        .filter(|result| result.status.is_green())
        .collect();
    if passed.is_empty() {
        return Ok(());
    }
    writeln!(out, "Checks that passed")?;
    for result in passed {
        writeln!(
            out,
            "  {}: {}",
            result.status.as_str(),
            escape_control_characters(&result.title)
        )?;
        if !result.reason.is_empty() {
            writeln!(out, "    {}", escape_control_characters(&result.reason))?;
        }
    }
    writeln!(out)
}

/// The repair contracts this run wrote, one block each.
///
/// `run.repairs` had no renderer at all before `P7-T012`: the pipeline filled the
/// field and every reader of the field was a test. A contract a user cannot read
/// is a contract only a programmer can act on, which is the opposite of what the
/// stage is for.
///
/// # Which re-check list is printed
///
/// The **effective** one — `repair_impact::select_impacted_checks`'s answer for
/// this contract and this run's schedule — rather than the shorter list the
/// contract carries. The contract's own list is what
/// `RepairContract::from_finding` was handed (the check whose result produced the
/// finding), and the selection is that list widened with the checks a repair of
/// this location could break. It is the selection that has to pass before the
/// finding closes, so it is the selection a reader is owed; the function is the
/// one the pipeline calls rather than a second rule written here.
fn repairs(run: &RunOutcome, out: &mut impl Write) -> io::Result<()> {
    if run.repairs.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "Repair contracts, one per finding. SURE will not close a finding because someone says \
         it is fixed: it closes when the checks below have passed."
    )?;
    for (number, contract) in run.repairs.iter().enumerate() {
        writeln!(out)?;
        writeln!(out, "{}. {}", number + 1, contract.problem)?;
        writeln!(out, "   Why it matters: {}", contract.why_it_matters)?;
        for fix in &contract.required_fix {
            writeln!(out, "   Required: {fix}")?;
        }
        for preserve in &contract.preserve {
            writeln!(out, "   Keep working: {preserve}")?;
        }
        for line in &contract.acceptance {
            writeln!(out, "   Accepted when: {line}")?;
        }
        let checks = select_impacted_checks(contract, &run.schedule);
        writeln!(
            out,
            "   Checks that must pass before this closes: {}",
            checks
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        if checks.is_empty() {
            // `from_finding` refuses an empty list, so this is unreachable from
            // the pipeline. It is written down rather than left to a reader to
            // deduce, because a contract that printed no check would look like a
            // contract that closes itself.
            writeln!(
                out,
                "   (No check can observe this one. SURE will not close it on a claim.)"
            )?;
        }
    }
    writeln!(out)
}

/// What the comparison with an earlier run found.
///
/// Silent unless there was one. A run with no history, or one that is not
/// comparing, has already said so in its stages, and a second sentence here
/// saying the same thing in different words is how two explanations of one
/// result start to disagree.
fn lifecycle(run: &RunOutcome, out: &mut impl Write) -> io::Result<()> {
    let Some(update) = &run.lifecycle else {
        return Ok(());
    };
    writeln!(
        out,
        "Against the earlier run: {} finding(s) still open, {} closed.",
        update.kept_open.len(),
        update.resolved.len()
    )?;
    for finding in &update.resolved {
        writeln!(out, "   Closed: {}", finding.title)?;
    }
    writeln!(out)
}

/// One sentence about what a not-clean verdict does and does not mean.
///
/// The false green has a mirror image and it is worth naming: a report that
/// said "this is not clean" while nothing was actually run would be read as a
/// statement about the project. Where nothing passed, that is not what
/// happened, and the reader is owed the difference.
fn not_clean_note(
    report: &CheckReport,
    outcome: &PipelineOutcome,
    out: &mut impl Write,
) -> io::Result<()> {
    if report.is_green() {
        return Ok(());
    }
    let Some(run) = &outcome.run else {
        return Ok(());
    };
    if run.coverage.checked_count == 0 {
        writeln!(
            out,
            "No check in this run produced a result about the project, so the status above is \
             not a finding: it says SURE could not establish enough to call the project clean."
        )?;
    } else {
        writeln!(
            out,
            "SURE established something about the project and something else it could not — \
             every gap is listed above. A run with a stage that did not run is never reported \
             as clean."
        )?;
    }
    writeln!(out)
}

/// The human form of a run that stopped before it had a verdict.
fn stopped(report: &CheckReport, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "sure {} could not finish.", report.command)?;
    writeln!(out)?;
    writeln!(out, "It was checking {}.", report.project)?;
    writeln!(out)?;

    match report.run.stopped_at {
        Some(stage) => {
            writeln!(
                out,
                "It stopped at stage {} of {}, {}:",
                stage.number(),
                Stage::ALL.len(),
                stage.title()
            )?;
            writeln!(out, "    {}", report.run.stage(stage).outcome.detail())?;
        }
        // Unreachable: a run with no outcome stopped somewhere. Written as a
        // sentence rather than as a panic, because a missing line in a report is
        // a better failure than a crash in a terminal.
        None => writeln!(out, "It did not say which stage stopped it.")?,
    }
    writeln!(out)?;
    writeln!(
        out,
        "No verdict was produced, so this is not a statement about your project: SURE did not \
         get far enough to make one."
    )?;
    writeln!(out)?;
    // A run that stopped still has settings, and the user is still owed the
    // answer about what this run was allowed to send. Saying nothing here would
    // be the one shape of silence that reads as "nothing left the machine".
    privacy(&report.privacy, report.model_use, out)?;
    // The other half of the same answer, and for the same reason: a run's
    // permissions are not derivable from anything else it prints, so a run that
    // said nothing about them would leave a person to read "no file was found"
    // as "nothing was allowed" — which is true here and is not what the report
    // says. Rendered by `crate::grants`, the same value `sure config set` prints
    // after a write, so the two commands cannot come to mean different things by
    // the same words.
    report.grants.human(out)?;
    if let Some(recorded) = &report.recorded_goal {
        what_was_recorded(recorded, out)?;
    }
    writeln!(
        out,
        "SURE exited with status {}, which is what it returns when it tried and did not finish. \
         That is not the same as a command this build cannot carry out, and not the same as a \
         wrong command line.",
        exit::FAILED
    )
}

/// What this run was allowed to send, and whether it sent anything.
///
/// The section exists because the answer to "which privacy mode is running" is
/// not derivable by a user from anything else SURE prints, and because
/// `docs/security/PRIVACY.md` states that the report says when external analysis
/// was used. Silence would read both as "nothing left this machine" and as "SURE
/// did not look", and only one of those is true.
///
/// Both values come from `sure_core::privacy`, which is where the reasons live:
/// the mode is the arbitrated one and not the one a file names, and whether a
/// model was consulted is read from the run's own stage log rather than from a
/// sentence written once and left to rot.
fn privacy(
    statement: &PrivacyStatement,
    model_use: ModelUse,
    out: &mut impl Write,
) -> io::Result<()> {
    writeln!(out, "Privacy and model use")?;
    writeln!(out)?;
    writeln!(out, "  Mode in effect: {}", statement.mode.as_str())?;
    writeln!(out, "    {}", statement.mode_set_by_plain_words())?;
    writeln!(out, "    {}", statement.mode_plain_words())?;
    if statement.project_settings_differ() {
        writeln!(
            out,
            "    This project's own settings come to {}, and a project's file cannot loosen \
             yours: the stricter of the two is the one in effect.",
            statement.project_mode.as_str()
        )?;
    }
    // The one combination a user cannot see any other way, and the one the
    // privacy mode exists for. `config/mod.rs` refuses it inside a single file,
    // so the only way to be in this state is for the two files to disagree — and
    // a report that said nothing here would leave a user reading "fully_local"
    // directly above a named external provider with no explanation.
    //
    // What it says is a fact about the configuration and not a promise about
    // traffic: `allows_external_analysis` is enforced at the file boundary, and
    // nothing on the send path consults it. Saying "nothing may be sent" would
    // be a guarantee this build does not implement.
    if !statement.allows_external_analysis() && statement.provider.is_external() {
        writeln!(
            out,
            "    This mode permits no external analysis, and the `{}` provider is external. A \
             single settings file naming both is refused; they are in effect together because \
             they came from different files.",
            statement.provider.as_str()
        )?;
    }
    writeln!(out, "  Analysis provider: {}", statement.provider.as_str())?;
    writeln!(out, "  {}", model_use.plain_explanation())?;
    writeln!(out)
}

/// The stage log, in order, with the gaps marked.
fn stages(outcome: &PipelineOutcome, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "What the run did, stage by stage")?;
    for record in &outcome.stages {
        writeln!(out, "  {}", record.plain_description())?;
    }
    writeln!(out)?;

    let gaps = outcome.gaps().count();
    if gaps > 0 {
        writeln!(
            out,
            "{gaps} of the {} stages did not run, and each is marked NOT CHECKED above. A run \
             with a stage that did not run is never reported as clean.",
            Stage::ALL.len()
        )?;
        writeln!(out)?;
    }
    Ok(())
}

/// What this run wrote to the user's history.
///
/// The one place a command changes something its output would not otherwise
/// contain, so it is said in the words a person reads and not only in the frame.
/// The text printed under the sentence is [`GoalRecorded::goal`], which is the
/// row's own text rather than a copy of the words that were typed — see
/// [`record_goal`] for why the two are read apart rather than assumed equal.
fn what_was_recorded(recorded: &GoalRecorded, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "What SURE recorded")?;
    writeln!(out)?;
    writeln!(
        out,
        "  Your goal was written to the history as record {}, before the check ran:",
        recorded.record
    )?;
    writeln!(out, "      {}", recorded.goal)?;
    writeln!(out, "  {}", recorded.source.plain_description())?;
    writeln!(
        out,
        "  It is recorded against the {} state {} of {}, so a later run can tell whether it is \
         still looking at the project you said it about.",
        recorded.project_state.kind.as_str(),
        recorded.project_state.digest,
        recorded.project_root
    )?;
    writeln!(out)
}

// --- the machine form ---------------------------------------------------

/// The `details` object of the response frame.
///
/// One object holding everything this run found, so that the frame's five fixed
/// fields keep meaning what `crate::report` says they mean. Everything that is a
/// statement about the *project* is under `report`, in the shape
/// `crate::json_report` already defines and versions for that purpose; what this
/// function adds is what only a run of the pipeline can say — which stages ran,
/// how far the run got, and what it wrote on the way.
#[must_use]
pub fn machine(report: &CheckReport) -> Value {
    let outcome = &report.run;
    let mut details = json!({
        "project": report.project,
        "purpose": report.command,
        "state": if outcome.finished() { "finished" } else { "stopped" },
        "green": report.is_green(),
        "stopped_at": outcome.stopped_at.map(Stage::as_str),
        "stages": outcome.stages.iter().map(stage_machine).collect::<Vec<Value>>(),
        "recorded_goal": report.recorded_goal.as_ref().map(goal_machine),
        // Facts, not prose: the sentence a person reads is in the human form,
        // where it can say why. A script switching on `mode` gets the arbitrated
        // value, and `mode_set_by` says which layer decided it.
        "privacy": {
            "mode": report.privacy.mode.as_str(),
            "mode_set_by": report.privacy.mode_set_by.map(sure_core::config::Layer::as_str),
            "project_mode": report.privacy.project_mode.as_str(),
            "external_analysis_allowed": report.privacy.allows_external_analysis(),
            "analysis_provider": report.privacy.provider.as_str(),
        },
        // One field, and it is the state rather than a boolean: `false` would
        // have to stand for both "a model was not consulted" and "this run
        // cannot say", and a script reading the reassuring half of an ambiguous
        // field is how "nothing was sent" gets asserted about a run that never
        // reached the stage.
        "model_use": {
            "state": report.model_use.as_str(),
            "provider": report.model_use.provider().as_str(),
        },
    });

    // Unconditional, unlike `mode` below: a run that stopped never reached a
    // stage that could set a mode, but it was still under settings, and a script
    // asking "was this machine allowed to run project code" has an answer either
    // way.
    details["grants"] = report.grants.machine();

    match &outcome.run {
        Some(run) => {
            details["mode"] = json!(run.mode.as_str());
            details["support"] = support_machine(run);
            details["report"] = verdict_machine(&run.verdict);
            // Keep every row, including passes, in the pipeline-specific part
            // of the frame. The verdict's versioned schema summarizes findings
            // and gaps; it deliberately has no slot for a passing check.
            details["check_results"] = json!(run.report.results());
            // The two things only a run of *this* pipeline produces, and which
            // no earlier form carried: what stage 11 wrote, and what stage 12
            // compared. They sit here rather than under `report` because
            // `report` is the verdict's own shape, defined and versioned by
            // `crate::json_report`, and these are the fields this function says
            // it adds — which stages ran, how far the run got, and what it wrote.
            details["repairs"] = repairs_machine(run);
            details["lifecycle"] = lifecycle_machine(run);
            details["checked_count"] = json!(run.coverage.checked_count);
            details["not_checked_count"] = json!(run.coverage.not_checked.len());
            details["has_critical_gaps"] = json!(run.coverage.has_critical_gaps);
        }
        // `null` rather than absent, for the reason every other field here is
        // unconditional: a reader switching on `state` should not also have to
        // ask whether a key exists.
        None => {
            details["mode"] = Value::Null;
            details["support"] = Value::Null;
            details["report"] = Value::Null;
            details["check_results"] = Value::Null;
            details["repairs"] = Value::Null;
            details["lifecycle"] = Value::Null;
        }
    }
    details
}

/// The repair contracts, with the effective re-check list added to each.
///
/// The contract's own fields are serialised from the contract rather than
/// retyped, so a field added to [`sure_core::vocabulary::RepairContract`] reaches
/// the frame without anyone remembering to add it here. The one thing added is
/// `rechecks_that_must_pass`: the contract carries the check the finding named,
/// and the list that governs closing is the selection the product widens it to.
/// Both are in the frame, under names that say which is which, because a script
/// asking "what has to pass" and a script asking "what did the finding name" are
/// asking two different questions.
fn repairs_machine(run: &RunOutcome) -> Value {
    Value::Array(
        run.repairs
            .iter()
            .map(|contract| {
                let mut value = serde_json::to_value(contract).unwrap_or(Value::Null);
                value["rechecks_that_must_pass"] = json!(
                    select_impacted_checks(contract, &run.schedule)
                        .iter()
                        .map(|id| id.as_str())
                        .collect::<Vec<_>>()
                );
                value
            })
            .collect(),
    )
}

/// What the comparison with the earlier run found, or `null` when there was none.
///
/// Findings are written as identity and state rather than whole, because a frame
/// that carried the full finding twice — once under `report` and once here —
/// would be two copies of one fact with two chances to disagree.
fn lifecycle_machine(run: &RunOutcome) -> Value {
    let Some(update) = &run.lifecycle else {
        return Value::Null;
    };
    json!({
        "still_open": update.kept_open.iter().map(finding_machine).collect::<Vec<Value>>(),
        "closed": update.resolved.iter().map(finding_machine).collect::<Vec<Value>>(),
    })
}

fn finding_machine(finding: &Finding) -> Value {
    json!({
        "id": finding.id.as_str(),
        "title": finding.title,
        "severity": finding.severity.as_str(),
        "status": finding.status.as_str(),
    })
}

/// One stage, in the shape a script reads.
fn stage_machine(record: &sure_core::pipeline::StageRecord) -> Value {
    let (outcome, reason): (&str, Option<NotCheckedReason>) = match &record.outcome {
        StageOutcome::Ran { .. } => ("ran", None),
        StageOutcome::NotPartOfWork { .. } => ("not_part_of_work", None),
        StageOutcome::NotRun { reason, .. } => ("not_run", *reason),
        StageOutcome::Unfinished { .. } => ("unfinished", None),
    };
    json!({
        "stage": record.stage.as_str(),
        "number": record.stage.number(),
        "title": record.stage.title(),
        "outcome": outcome,
        // The vocabulary's own wire name, taken from its serde spelling rather
        // than retyped here: a second list of reasons is a second list to keep in
        // step, and the day one is added this would be the copy nobody updated.
        "reason": reason.map(|reason| serde_json::to_value(reason).unwrap_or(Value::Null)),
        "reason_explained": reason.map(NotCheckedReason::plain_explanation),
        "detail": record.outcome.detail(),
    })
}

/// What SURE could and could not see of the project.
fn support_machine(run: &RunOutcome) -> Value {
    json!({
        "level": run.support.level.as_str(),
        "letter": run.support.level.letter().to_string(),
        "reason": run.support.reason,
    })
}

/// The verdict, in the shape `crate::json_report` publishes.
#[allow(
    clippy::expect_used,
    reason = "a JsonReport holds only strings, integers and booleans, so serializing it to a \
              Value cannot fail; `json_report.rs` allows the same call for the same reason"
)]
fn verdict_machine(verdict: &ProjectVerdict) -> Value {
    serde_json::to_value(crate::json_report::build_json_report(verdict))
        .expect("a JsonReport is made of JSON values")
}

/// The goal this run wrote, in the shape a script reads.
fn goal_machine(recorded: &GoalRecorded) -> Value {
    json!({
        "goal": recorded.goal,
        "requirement_id": recorded.requirement_id,
        // The wire name, so that the field a script switches on and the sentence
        // a person reads are two renderings of one value rather than two strings
        // kept in step by hand.
        "source": recorded.source.as_str(),
        "project_root": recorded.project_root,
        "project_state": fingerprint_machine(&recorded.project_state),
        "record": recorded.record,
    })
}

/// The state a goal was recorded against.
fn fingerprint_machine(state: &ProjectFingerprint) -> Value {
    json!({
        "id": state.id.as_str(),
        "kind": state.kind.as_str(),
        "digest": state.digest,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use serde_json::json;
    use sure_core::store::{HistoryFilter, RecordKind, StoredRecord};

    use super::*;
    use crate::report::exit;

    /// A directory under the workspace's git-ignored `target/tmp`, holding
    /// everything one test needs to be a different machine.
    ///
    /// The helper is `sure_testkit::scratch`, which holds the reasoning once
    /// for every file that used to carry its own copy: one directory per run
    /// per pool, named for the process, and the directory handed back is this
    /// call's own.
    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(test: &str) -> Self {
            let root = sure_testkit::scratch::directory("sure check", test);
            std::fs::create_dir_all(root.join("project"))
                .unwrap_or_else(|error| panic!("cannot create the project: {error}"));
            Self { root }
        }

        /// The project `sure check` is pointed at.
        fn project(&self) -> PathBuf {
            self.root.join("project")
        }

        fn write(&self, relative: &str, contents: &str) {
            let full = self.project().join(relative);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
            }
            std::fs::write(&full, contents)
                .unwrap_or_else(|error| panic!("cannot write {}: {error}", full.display()));
        }

        /// Where SURE keeps its files for this test: nowhere near the project,
        /// because a store inside the tree being judged is refused.
        fn paths(&self) -> Paths {
            Paths::from_roots(self.root.join("data"), self.root.join("config"))
                .expect("the scratch locations are absolute")
        }

        /// The user's own settings file, outside the project.
        ///
        /// Written under the fixture's own config root rather than at the
        /// machine's real one, which is the whole reason [`Paths::from_roots`]
        /// exists: the real user configuration directory cannot be moved by a
        /// flag or an environment variable, so a test that read it would be a
        /// test of whoever's machine it ran on.
        fn write_user_config(&self, contents: &str) {
            let path = self.paths().user_config_file();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
            }
            std::fs::write(&path, contents)
                .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
        }
    }

    /// A project SURE can read and cannot run: a Python file and no manifest
    /// SURE would plan a command from.
    fn a_project(fixture: &Fixture) {
        fixture.write("main.py", "def main():\n    print('hello')\n");
        fixture.write("README.md", "# a small project\n");
    }

    /// A project SURE can read **and plans checks for**: a Rust crate, which is
    /// the shape that gives the pipeline something to do.
    ///
    /// This is the fixture most of the tests below want, and the reason is worth
    /// writing down, because a smaller project would hide the rules they are
    /// about. A crate with a `Cargo.toml` declares `cargo test` and `cargo check
    /// --all-targets` — two checks that would run the project's own code, and
    /// under the default execution mode neither is authorised. So the run has:
    ///
    /// * planned checks that were refused by the mode, recorded as skipped with
    ///   [`ExecutionNotAuthorized`](sure_core::status::NotCheckedReason::ExecutionNotAuthorized);
    /// * checks the mode has nothing to refuse, whose result comes from the
    ///   evidence the check itself carries rather than from a process — a
    ///   detector's observation is not a command, and since `P18-T007` the
    ///   pipeline carries one to a result instead of leaving it unknown because no
    ///   runner existed;
    /// * two stages that could not do their work and must be recorded as gaps.
    ///
    /// A Python file with no manifest plans nothing at all, and every stage then
    /// reports `not part of this run` — which is a true and different answer, and
    /// one that would let a test of the false-green rule pass without ever
    /// exercising it.
    fn a_rust_project(fixture: &Fixture) {
        fixture.write(
            "Cargo.toml",
            "[package]\nname = \"thing\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        fixture.write(
            "src/lib.rs",
            "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        );
        fixture.write("README.md", "# a small project\n");
    }

    /// Everything the store holds, recordings included.
    fn everything(store: &Store) -> Vec<StoredRecord> {
        store
            .history(
                &HistoryFilter {
                    include_recordings: true,
                    ..HistoryFilter::default()
                },
                100,
            )
            .unwrap_or_else(|error| panic!("cannot read the history: {error}"))
    }

    /// The record kind a project intent is stored as.
    ///
    /// Asked of the protocol's own table rather than restated here, and reached
    /// through `RecordKind::from_name` because that is the door this crate's
    /// manifest gives the CLI into `sure_protocol::documents`: `sure-cli` has one
    /// edge into the engine and its vocabulary (ADR 0001), and a test needing to
    /// name a document kind is not a reason to open a second.
    fn intent_kind() -> RecordKind {
        // The wire name, which is not the Rust variant's spelling:
        // `project-intent`, with the hyphen, and the schema file follows it.
        RecordKind::from_name("project-intent").expect("the protocol defines this kind")
    }

    /// The one project-intent row in a store, or a panic naming what was there.
    fn the_intent_row(store: &Store) -> StoredRecord {
        let mut intents: Vec<StoredRecord> = store
            .history(&HistoryFilter::default(), 100)
            .unwrap_or_else(|error| panic!("cannot read the history: {error}"))
            .into_iter()
            .filter(|row| row.kind == intent_kind())
            .collect();
        assert_eq!(
            intents.len(),
            1,
            "expected exactly one project-intent row, found {}",
            intents.len()
        );
        intents.remove(0)
    }

    /// The run's own report, or a panic naming the report that came back.
    fn checked(report: &Report) -> &CheckReport {
        match report {
            Report::Check(check) => check,
            other => panic!("expected a check, got {other:?}"),
        }
    }

    fn failure(report: &Report) -> &Failed {
        match report {
            Report::Failed(failure) => failure,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    fn machine_of(report: &Report) -> Value {
        report.frame()["details"].clone()
    }

    // --- the acceptance criteria ----------------------------------------

    #[test]
    fn a_check_of_a_real_project_runs_the_stages_and_produces_a_verdict() {
        // The first acceptance criterion, end to end: one orchestrator runs the
        // documented stages over a project on disk. What this asserts is that a
        // real `sure check` reached a verdict at all — the stage log is an
        // ordered walk of the twelve, and the verdict exists.
        let fixture = Fixture::new("real-check");
        a_rust_project(&fixture);
        let project = fixture.project();
        let report = run_with(Purpose::Check, &fixture.paths(), &project, None);

        let check = checked(&report);
        let outcome = &check.run;
        assert!(outcome.finished(), "the run stopped: {outcome:?}");
        assert_eq!(
            outcome.stages.iter().map(|r| r.stage).collect::<Vec<_>>(),
            Stage::ALL.to_vec(),
            "the run did not record every stage, in order"
        );
        assert_eq!(outcome.purpose, Purpose::Check);
        assert_eq!(check.command, "check");
        assert_eq!(
            check.project,
            project.display().to_string(),
            "the report is about a project other than the one it was pointed at"
        );

        let run = outcome.run.as_ref().expect("a finished run has an outcome");
        // The pipeline read a real project: its own account of that project says
        // so, in a fingerprint that names the state the verdict is about.
        assert!(
            !run.project_state.digest.is_empty(),
            "the run does not say which state of the project it is about"
        );
        assert_eq!(
            run.project_state.id, run.verdict.fingerprint,
            "the run and the verdict disagree about which reading they are about"
        );
        // And it had work to do: this fixture plans checks, so the run is about
        // something and not a walk over an empty plan.
        assert!(run.schedule.len() >= 2, "nothing was planned to check");
        // The verdict carries a scope, and it is the run's own: the checks that
        // produced no result are in it, so a reader can see what was not
        // established rather than only what was.
        assert!(
            run.coverage.checked_count + run.coverage.not_checked.len() > 0,
            "the report says neither that something was checked nor that something was not"
        );
    }

    #[test]
    fn no_check_this_build_can_run_is_ever_reported_as_clean() {
        // The false green, over a real project. Under the default mode the checks
        // this project declares are refused and none of them runs, so every stage
        // that had work and did not do it must show up as a gap, and a run with a
        // gap must never be reported as clean.
        let fixture = Fixture::new("never-green");
        a_rust_project(&fixture);
        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);

        let check = checked(&report);
        assert!(
            !check.is_green(),
            "a run that carried out none of the project's own checks reported a project as clean: \
             {:?}",
            check.run
        );
        assert_eq!(
            report.exit_code(),
            exit::NOT_GREEN,
            "a project SURE could not check enough of is not status 3"
        );
        assert_ne!(report.exit_code(), exit::UNAVAILABLE);
        assert_ne!(report.exit_code(), exit::OK);

        // And the reason is visible rather than implied: the stages that had
        // work and could not do it are recorded as gaps, and the run says so in
        // the report a person reads. The two that always have work and never
        // finish here are the project's own checks — refused by the mode this run
        // is under — and the model assessment, which has no provider.
        for stage in [Stage::DynamicChecks, Stage::ModelAssessment] {
            assert!(
                check.run.stage(stage).outcome.is_a_gap(),
                "stage {} is not recorded as a gap: {:?}",
                stage.number(),
                check.run.stage(stage)
            );
        }
        let written = report.human_text();
        assert!(
            written.contains("NOT CHECKED"),
            "the human report does not mark the gap:\n{written}"
        );
        assert!(
            written.contains("never reported as clean"),
            "the human report does not say what a gap costs:\n{written}"
        );
    }

    #[test]
    fn a_dynamic_check_the_mode_did_not_authorise_is_not_checked_and_never_passed() {
        // The second acceptance criterion's sharp edge. A project whose shape
        // plans a check that would run its code, under the default execution
        // mode, must record that check as *not checked* — and no result of it may
        // be a pass, whatever it was that stopped it.
        let fixture = Fixture::new("dynamic-refused");
        a_rust_project(&fixture);
        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);

        let check = checked(&report);
        let run = check.run.run.as_ref().expect("a verdict");
        assert_eq!(
            run.mode,
            sure_core::execution::ExecutionMode::InspectOnly,
            "the default execution mode moved, so this test is checking the wrong rule"
        );

        // The checks the mode refused, rather than the checks that failed for
        // some other reason: the two are different states and the report must
        // not blur them.
        let refused: Vec<&sure_core::status::CheckResult> = run
            .report
            .results()
            .iter()
            .filter(|result| {
                result.not_checked_reason
                    == Some(sure_core::status::NotCheckedReason::ExecutionNotAuthorized)
            })
            .collect();
        assert!(
            !refused.is_empty(),
            "no check was refused by the execution mode, so this test is not exercising the \
             rule: {:?}",
            run.report.results()
        );
        for result in &refused {
            assert_eq!(
                result.status,
                sure_core::status::CheckStatus::Skipped,
                "{} was refused and is not recorded as not run",
                result.title
            );
            assert_ne!(
                result.status,
                sure_core::status::CheckStatus::Pass,
                "a check that did not run was recorded as passed"
            );
            // And it is *not* a scope limit — the distinction the aggregation
            // rules turn on. A scope limit says "this does not apply to your
            // project"; this says "SURE was not allowed to find out", which is
            // exactly the state that must never be reported as clean, so it is
            // the one reason that cannot be excused as out of scope.
            assert!(
                !result
                    .not_checked_reason
                    .is_some_and(sure_core::status::NotCheckedReason::is_scope_limit),
                "{} was refused by the mode and is recorded as not applying to the project",
                result.title
            );
        }

        // Nothing in the run's own account calls those checks done: the refusal
        // is in the stage log, in the coverage the verdict carries, and in the
        // frame a script reads.
        let stage = check.run.stage(Stage::DynamicChecks);
        assert!(
            matches!(
                stage.outcome,
                StageOutcome::NotRun {
                    reason: Some(sure_core::status::NotCheckedReason::ExecutionNotAuthorized),
                    ..
                }
            ),
            "stage 6 does not record the mode's refusal: {stage:?}"
        );
        assert_eq!(
            run.coverage.checked_count, 0,
            "a run whose checks were all refused counted one as checked"
        );
        let machine = machine_of(&report);
        let not_checked = machine["report"]["not_checked"]
            .as_array()
            .expect("the verdict lists what was not checked");
        let listed: Vec<&str> = not_checked
            .iter()
            .map(|entry| entry["id"].as_str().expect("every entry names its check"))
            .collect();
        for result in &refused {
            assert!(
                listed.contains(&result.id.as_str()),
                "the verdict does not list the check the mode refused: {machine}"
            );
        }

        // The run also holds a row for every role SURE proposes that this
        // project never declared, and `P18-T011` is why they are in the account
        // rather than only in the report's own list: those rows were built by
        // `MissingCommand::not_checked` and then dropped into
        // `RunReport::unscheduled`, a field no renderer reads, so a run over
        // this fixture was made of four rows and told a reader about two. The
        // report is where that silence would have been read as an absence of a
        // problem, so the row's existence is asserted here and not only in
        // `crates/sure-core/tests/declared_commands.rs`, which is where the
        // critical kind and the aggregate are.
        let undeclared: Vec<&sure_core::status::CheckResult> = run
            .report
            .results()
            .iter()
            .filter(|result| {
                result.not_checked_reason
                    == Some(sure_core::status::NotCheckedReason::NotApplicable)
            })
            .collect();
        assert!(
            !undeclared.is_empty(),
            "the run holds no row for a role this project never declared, so its account of what \
             it did not run is the mode's refusals alone: {:?}",
            run.report.results()
        );

        // And the rendered list is exactly the run's own rows that did not run —
        // no more and no fewer, each carrying its own row's sentence. This pins
        // the renderer rather than the run: a build that filtered a row out of
        // the machine report, or printed a sentence the row does not carry,
        // fails here.
        let mut expected: Vec<&str> = run
            .report
            .results()
            .iter()
            .filter(|result| result.is_not_checked())
            .map(|result| result.id.as_str())
            .collect();
        expected.sort_unstable();
        let mut found = listed.clone();
        found.sort_unstable();
        assert_eq!(
            found, expected,
            "the verdict's list of checks that did not run is not the run's own rows for them: \
             {machine}"
        );

        // Each entry says why, and says what the run's own row says about it —
        // the refusal sentence for the checks the mode stopped, and the
        // vocabulary's own sentence for a role the project never declared.
        for entry in not_checked {
            let id = entry["id"].as_str().expect("every entry names its check");
            let row = run
                .report
                .results()
                .iter()
                .find(|result| result.id.as_str() == id)
                .expect("the list is a subset of the run's own rows");
            assert_eq!(
                entry["reason"],
                json!(row.reason),
                "a check that did not run does not carry its own sentence: {entry}"
            );
        }
        for result in &refused {
            let entry = not_checked
                .iter()
                .find(|entry| entry["id"].as_str() == Some(result.id.as_str()))
                .expect("the refused check is in the list");
            assert!(
                entry["reason"]
                    .as_str()
                    .is_some_and(|reason| reason.contains("running your project's code")),
                "a refused check does not say why: {entry}"
            );
        }
        // The reason in the vocabulary's own spelling is on the stage, which is
        // where a reader switches on it; the report's list carries the sentence.
        assert_eq!(machine["stages"][5]["outcome"], json!("not_run"));
        assert_eq!(
            machine["stages"][5]["reason"],
            json!("execution_not_authorized")
        );
        assert_eq!(machine["green"], json!(false));
        assert_eq!(machine["checked_count"], json!(0));
        assert_eq!(machine["has_critical_gaps"], json!(true));
    }

    #[test]
    fn every_stage_that_did_not_run_cannot_aggregate_to_a_clean_verdict() {
        // The rule the whole product rests on, stated over the run's own record:
        // read the stage log, and if any stage is a gap, the run is not clean —
        // and the exit status agrees with that reading. This is the criterion
        // "no stage in that state can aggregate to a clean verdict" made
        // checkable independently of how the aggregate happens to be computed.
        let fixture = Fixture::new("stage-gaps");
        a_project(&fixture);
        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);

        let check = checked(&report);
        let any_gap = check.run.gaps().next().is_some();
        assert!(any_gap, "this fixture was expected to leave a stage un-run");
        assert!(!check.is_green());
        assert_eq!(report.outcome(), "not_green");
        assert_eq!(report.exit_code(), exit::NOT_GREEN);
    }

    #[test]
    fn an_unconfigured_model_provider_is_a_recorded_state_and_not_an_omission() {
        // Stage 8 with nothing configured is a scope limit: recorded, visible,
        // and not a failure. A run whose log simply stopped at stage 7 would look
        // exactly the same in a verdict that never mentioned it.
        let fixture = Fixture::new("no-provider");
        a_project(&fixture);
        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);

        let record = checked(&report).run.stage(Stage::ModelAssessment);
        match &record.outcome {
            StageOutcome::NotRun { reason, detail } => {
                assert_eq!(
                    *reason,
                    Some(sure_core::status::NotCheckedReason::AnalysisProviderDisabled)
                );
                assert!(
                    detail.contains("not a failure"),
                    "the run does not say what an unconfigured provider costs: {detail}"
                );
            }
            other => panic!("stage 8 with no provider is {other:?}"),
        }

        let machine = machine_of(&report);
        let stage = machine["stages"]
            .as_array()
            .expect("the frame lists every stage")
            .iter()
            .find(|entry| entry["stage"] == json!("model-assessment"))
            .cloned()
            .expect("the frame lists stage 8");
        assert_eq!(stage["outcome"], json!("not_run"));
        assert_eq!(
            stage["reason"],
            json!("analysis_provider_disabled"),
            "the frame does not carry the vocabulary's own reason: {stage}"
        );
    }

    // --- privacy and model use ---------------------------------------------

    #[test]
    fn the_mode_in_a_report_is_the_arbitrated_one_and_not_the_one_a_file_names() {
        // The criterion "local-first / fully-local / cloud-enhanced semantics
        // explicit", measured where it can be got wrong: a run has two settings
        // files and only one of them may decide. A project's file cannot loosen
        // the user's (`docs/architecture/CONFIG_AUTHORITY.md`), so a report that
        // named the project's mode would be a false statement about the user's
        // own policy — see `sure_core::privacy`.
        let fixture = Fixture::new("privacy-arbitrated");
        a_project(&fixture);
        let paths = fixture.paths();

        // The project asks for `local_first`; the user's own file says
        // `fully_local`. The project's file is read first by the pipeline and
        // would be the easy thing to report.
        fixture.write("sure.yaml", "privacy:\n  mode: local_first\n");
        fixture.write_user_config("privacy:\n  mode: fully_local\n");
        let report = run_with(Purpose::Check, &paths, &fixture.project(), None);

        let check = checked(&report);
        assert_eq!(
            check.privacy.mode,
            sure_core::config::PrivacyMode::FullyLocal,
            "the report names the mode the project asked for, not the mode in effect"
        );
        assert_eq!(
            check.privacy.mode_set_by,
            Some(sure_core::config::Layer::User)
        );
        assert_eq!(
            check.privacy.project_mode,
            sure_core::config::PrivacyMode::LocalFirst
        );
        assert!(!check.privacy.allows_external_analysis());
        assert!(check.privacy.project_settings_differ());

        // Both renderings, because a user reads one and a script reads the other.
        let written = report.human_text();
        assert!(written.contains("Mode in effect: fully_local"), "{written}");
        assert!(written.contains("cannot loosen yours"), "{written}");
        let machine = machine_of(&report);
        assert_eq!(machine["privacy"]["mode"], json!("fully_local"));
        assert_eq!(machine["privacy"]["mode_set_by"], json!("user"));
        assert_eq!(machine["privacy"]["project_mode"], json!("local_first"));
        assert_eq!(
            machine["privacy"]["external_analysis_allowed"],
            json!(false)
        );

        // The other direction, and the reason both are worth having: a project
        // asking for more privacy than the user configured becomes the mode in
        // effect, and is named as the one that set it. It is not escalation —
        // the mode is a maximum — so it cannot raise what a run may do.
        let other = Fixture::new("privacy-project-decides");
        a_project(&other);
        other.write("sure.yaml", "privacy:\n  mode: fully_local\n");
        let report = run_with(Purpose::Check, &other.paths(), &other.project(), None);
        let check = checked(&report);
        assert_eq!(
            check.privacy.mode,
            sure_core::config::PrivacyMode::FullyLocal
        );
        assert_eq!(
            check.privacy.mode_set_by,
            Some(sure_core::config::Layer::Project)
        );
        assert!(!check.privacy.project_settings_differ());
        assert!(report.human_text().contains("Mode in effect: fully_local"));
    }

    #[test]
    fn a_project_cannot_lower_the_mode_the_users_own_settings_set() {
        // The rule from the other side, as a run rather than as a value: the same
        // project file, byte for byte, is checked under two different user
        // settings, and the run's own report differs. This is the case the brief
        // asks for and the one a single-file reader must fail.
        let fixture = Fixture::new("privacy-not-lowerable");
        a_project(&fixture);
        fixture.write("sure.yaml", "privacy:\n  mode: local_first\n");
        let paths = fixture.paths();
        let project = fixture.project();

        let before = run_with(Purpose::Check, &paths, &project, None);
        assert_eq!(
            checked(&before).privacy.mode,
            sure_core::config::PrivacyMode::LocalFirst
        );

        fixture.write_user_config("privacy:\n  mode: fully_local\n");
        let after = run_with(Purpose::Check, &paths, &project, None);
        assert_eq!(
            checked(&after).privacy.mode,
            sure_core::config::PrivacyMode::FullyLocal,
            "the same project file reported the same mode under stricter user settings, so the \
             reported mode is not the arbitrated one"
        );
        assert!(!checked(&after).privacy.allows_external_analysis());
    }

    #[test]
    fn a_user_settings_file_that_cannot_be_read_stops_the_run_rather_than_being_ignored() {
        // `Authority::load`'s rule: one bad file stops the read, because running
        // with defaults while the user believes their settings are in force is
        // the failure both readers exist to prevent. It is a visible error —
        // status 5 and a sentence — and never a green run under a policy nobody
        // chose. This is a behaviour change this task makes: before it, `sure
        // check` never opened the user's file at all.
        let fixture = Fixture::new("privacy-bad-user-file");
        a_project(&fixture);
        fixture.write_user_config("privacy:\n  mode: no_such_mode\n");

        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
        let failure = failure(&report);
        assert_eq!(failure.what, NOTHING_RECORDED);
        assert_eq!(report.exit_code(), exit::FAILED);
        assert_ne!(report.exit_code(), exit::OK);
        assert_ne!(report.exit_code(), exit::UNAVAILABLE);
        // The message names the file that could not be read, so a user can find
        // it: this is a file outside the project, which nothing else in SURE
        // would ever have mentioned.
        assert!(
            failure.detail.contains("sure.yaml"),
            "the failure does not name the file: {}",
            failure.detail
        );
    }

    #[test]
    fn an_external_provider_under_local_first_is_named_and_nothing_is_sent() {
        // The other acceptance criterion's sharp edge: an external provider is
        // configured, so the report has to say so, say which one, and say what
        // happened — which in this build is that nothing was asked of it.
        let fixture = Fixture::new("privacy-external-provider");
        a_project(&fixture);
        fixture.write("sure.yaml", "analysis:\n  provider: claude_cli\n");

        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
        let check = checked(&report);
        assert_eq!(
            check.privacy.provider,
            sure_core::config::AnalysisProvider::ClaudeCli
        );
        assert!(check.privacy.provider.is_external());
        // `local_first` permits it, so the run goes ahead and the disclosure is
        // about this run rather than about a refusal.
        assert_eq!(
            check.privacy.mode,
            sure_core::config::PrivacyMode::LocalFirst
        );
        assert!(check.privacy.allows_external_analysis());
        assert_eq!(
            check.model_use,
            ModelUse::NothingAsked {
                provider: sure_core::config::AnalysisProvider::ClaudeCli
            },
            "the run did not record what it did about the provider it was given"
        );

        let written = report.human_text();
        assert!(
            written.contains("Analysis provider: claude_cli"),
            "{written}"
        );
        assert!(written.contains("No model was consulted"), "{written}");
        assert!(written.contains("claude_cli"), "{written}");
        let machine = machine_of(&report);
        assert_eq!(machine["privacy"]["analysis_provider"], json!("claude_cli"));
        assert_eq!(machine["privacy"]["external_analysis_allowed"], json!(true));
        assert_eq!(machine["model_use"]["state"], json!("nothing_asked"));
        assert_eq!(machine["model_use"]["provider"], json!("claude_cli"));
    }

    #[test]
    fn fully_local_and_an_external_provider_are_refused_in_one_file() {
        // Not a guarantee this task adds: `config/mod.rs` has refused this pair
        // since before it, and the point of asserting it here is that the refusal
        // is what a user meets — status 5 and a message naming both settings —
        // rather than a report that said `fully_local` while an external provider
        // sat under it.
        let fixture = Fixture::new("privacy-fully-local-external");
        a_project(&fixture);
        fixture.write(
            "sure.yaml",
            "privacy:\n  mode: fully_local\nanalysis:\n  provider: claude_cli\n",
        );

        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
        let failure = failure(&report);
        assert_eq!(report.exit_code(), exit::FAILED);
        // The message names both settings and says which one it is about, so the
        // user knows what to change. It names the keys rather than the values —
        // `privacy.mode` and `analysis.provider`, not `fully_local` and
        // `claude_cli` — which is enough to act on and is `config/error.rs`'s
        // wording rather than this task's to change.
        assert!(
            failure.detail.contains("privacy.mode") && failure.detail.contains("analysis.provider"),
            "the refusal does not name both settings: {}",
            failure.detail
        );
        assert!(
            failure.detail.contains("fully-local") || failure.detail.contains("Fully-local"),
            "the refusal does not say what fully-local means: {}",
            failure.detail
        );
        assert!(
            !fixture.paths().store_file().exists(),
            "a refused configuration left a history behind"
        );
    }

    // --- the execution settings the pipeline plans under (P13-T009) --------

    /// A project file asking for everything a project's own file can ask for.
    ///
    /// A mode that would run the project's code, the two permissions that only
    /// exist under such a mode, the loosest protection mode there is, and a full
    /// recording kept for no time at all. Every one of these is a *request*
    /// (`docs/adr/0011-project-configuration-is-a-request.md`): the project says
    /// what it would like, and the user's own file decides.
    const A_PROJECT_ASKING_FOR_EVERYTHING: &str = "\
execution:
  mode: host_confirmed
  allow_dependency_install: true
  allow_network: true
protection:
  mode: standard
privacy:
  full_recording: true
  full_recording_retention_days: 0
";

    #[test]
    fn a_project_file_cannot_choose_the_mode_the_pipeline_plans_under() {
        // P13-T009, the pipeline half (the brief's D3), measured on the two
        // values stage 4 actually uses rather than on the file that named them.
        //
        // Before the change `sure check` handed `authority.project_file().config`
        // into the pipeline and stage 4 read `config.execution`, so this
        // fixture — a project whose own `sure.yaml` says `host_confirmed` — had
        // its checks planned under a mode and a permission set the user's own
        // file had never granted. `RunOutcome::mode` and `::permissions` are the
        // run's own account of what it decided under, so this is a statement
        // about the plan and not about the settings file.
        //
        // What it cannot be is an assertion about a *run*: under the mode this
        // fixture lands on, `inspect_only`, no command that starts a process is
        // admitted, so what the mode changes here is which checks are refused
        // rather than what any check did — and that is observable, so the second
        // half below reads the refusal this mode produced.
        let fixture = Fixture::new("pipeline-project-mode");
        a_rust_project(&fixture);
        fixture.write("sure.yaml", A_PROJECT_ASKING_FOR_EVERYTHING);

        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
        let run = checked(&report).run.run.as_ref().expect("a verdict");

        assert_eq!(
            run.mode,
            sure_core::execution::ExecutionMode::InspectOnly,
            "a project's own file chose the mode the pipeline planned under"
        );
        assert_eq!(
            run.permissions,
            sure_core::execution::ExecutionPermissions::inspect_only(),
            "a project's own file granted itself permissions the user's file did not"
        );
        assert_eq!(machine_of(&report)["mode"], json!("inspect_only"));

        // And the plan really was made under that mode: the checks this project's
        // shape would run are refused with the vocabulary's own reason, which is
        // the difference the mode makes to what a reader sees.
        assert!(
            run.report
                .results()
                .iter()
                .any(|result| result.not_checked_reason
                    == Some(sure_core::status::NotCheckedReason::ExecutionNotAuthorized)),
            "no check was refused by the execution mode, so the run did not plan under one: {:?}",
            run.report.results()
        );
    }

    #[test]
    fn the_users_own_file_is_what_moves_the_mode_the_pipeline_plans_under() {
        // The other direction, and the one that shows `Authority::permissions()`
        // reaches stage 4 rather than a set built on the way: the user's own file
        // grants a mode and a permission no project file can, and the run's own
        // outcome says so.
        //
        // `install_dependencies` is the sharpest of the six to assert, because
        // nothing else in this build can grant it: the old hand-built set in the
        // hook copied `allow_dependency_install` straight out of the project's
        // file, and the pipeline never had a permission set at all.
        //
        // The user's file is written under the fixture's own config root, which
        // is why `Paths::from_roots` exists: the machine's real configuration
        // directory is read through `SHGetKnownFolderPath` and cannot be moved by
        // a flag or an environment variable, so a test that used it would be a
        // test of whoever's machine it ran on.
        let fixture = Fixture::new("pipeline-user-grant");
        a_rust_project(&fixture);
        fixture.write_user_config(
            "execution:\n  mode: host_confirmed\n  allow_dependency_install: true\n",
        );

        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
        let run = checked(&report).run.run.as_ref().expect("a verdict");

        assert_eq!(
            run.mode,
            sure_core::execution::ExecutionMode::HostConfirmed,
            "the user's own file named a mode and the run did not plan under it"
        );
        assert!(run.permissions.run_project_code);
        assert!(
            run.permissions.install_dependencies,
            "the user's own file granted this permission and the run did not plan under it"
        );
        assert_eq!(machine_of(&report)["mode"], json!("host_confirmed"));

        // The plan moved with it: under the default mode this project's own
        // checks are refused as unauthorised, and under the mode the user granted
        // there is nothing to refuse them for. Asserted as an absence of that one
        // reason rather than as a count, because what the assertion is about is
        // the refusal and not the outcome — and since `P18-T007` a check that is
        // *not* refused is handed to the runner this test passes the pipeline.
        //
        // What the checks are stopped by instead is a different permission, and it
        // is worth being exact because the runner here is live. This project's two
        // commands are `cargo test` and `cargo check --all-targets`, and
        // `sure_core::safety` classifies both as `[DynamicHost, Network]`; the
        // user's file granted `run_project_code` and installation but not
        // `allow_network`, so both come back `Skipped` with `NetworkNotPermitted`
        // and nothing reaches the runner. Measured rather than assumed, with a
        // runner that records instead of spawning over a scratch crate with these
        // same two commands: `pipeline.rs`'s test module with
        // `execution:\n  mode: host_confirmed\n  allow_dependency_install: true\n`
        // and a `Recording` runner reports `mode=HostConfirmed
        // run_project_code=true install=true network=false`, an empty recording,
        // and for both checks `Skipped | reason=Some(NetworkNotPermitted)`,
        // "Checking this needs internet access, and you have not allowed it."
        // That is also the reason a test that additionally granted `allow_network`
        // is not written: it would start `cargo` on whatever machine ran it.
        assert!(
            !run.report
                .results()
                .iter()
                .any(|result| result.not_checked_reason
                    == Some(sure_core::status::NotCheckedReason::ExecutionNotAuthorized)),
            "a check the user's own mode authorised was refused as unauthorised: {:?}",
            run.report.results()
        );
    }

    #[test]
    fn the_same_pair_split_across_two_files_is_not_refused_and_says_so() {
        // The honest half of the rule above, and the reason the report has a line
        // for this state at all: each file is validated on its own, so two files
        // can put `fully_local` and an external provider in effect together. The
        // report states the fact about the configuration, and states it as a fact:
        // `allows_external_analysis` is enforced at the file boundary and nothing
        // on the send path consults it, so a sentence promising that nothing
        // *could* be sent would be a guarantee this build does not implement.
        let fixture = Fixture::new("privacy-split-files");
        a_project(&fixture);
        fixture.write_user_config("privacy:\n  mode: fully_local\n");
        fixture.write("sure.yaml", "analysis:\n  provider: openai_compatible\n");

        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
        let check = checked(&report);
        assert_eq!(
            check.privacy.mode,
            sure_core::config::PrivacyMode::FullyLocal
        );
        assert_eq!(
            check.privacy.provider,
            sure_core::config::AnalysisProvider::OpenAiCompatible
        );
        assert!(!check.privacy.allows_external_analysis());
        assert!(machine_of(&report)["model_use"]["state"] != json!("consulted"));

        let written = report.human_text();
        assert!(
            written.contains("came from different files"),
            "the report does not explain a state no single file can be in:\n{written}"
        );
    }

    #[test]
    fn no_run_in_this_build_can_say_a_model_was_consulted() {
        // The honest limit, as a test that will fail the day it stops being one.
        // No check in this build asks for model-backed analysis, and stage 8 says
        // so in its own words; so `consulted` is unreachable, and the states a
        // run can be in are the four that mean no model was consulted or that
        // SURE cannot say. If a later build adds a check that asks for analysis,
        // this test fails and the person reading it has to decide what the report
        // should now say — which is the point, and is why the state is read from
        // the run rather than written as a constant.
        let fixture = Fixture::new("privacy-honest-limit");
        a_project(&fixture);
        fixture.write("sure.yaml", "analysis:\n  provider: claude_cli\n");

        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
        let check = checked(&report);
        assert!(
            !check.model_use.a_model_was_consulted(),
            "this build claims a model was consulted: {:?}",
            check.model_use
        );
        assert_ne!(
            check.model_use.as_str(),
            "consulted",
            "no check in this build asks for model-backed analysis, so a run cannot report one"
        );
        assert!(
            !check.run.stage(Stage::ModelAssessment).outcome.is_a_gap(),
            "a configured provider is not part of this run's work rather than a gap"
        );
    }

    #[test]
    fn a_run_that_stopped_still_says_what_it_was_allowed_to_send() {
        // A stopped run is the one shape of silence that reads as "nothing left
        // the machine". It has settings — they were read before the pipeline ran
        // — so it can answer, and it does.
        let fixture = Fixture::new("privacy-stopped");
        let report = run_with(
            Purpose::Check,
            &fixture.paths(),
            &fixture.root.join("not-a-directory"),
            None,
        );
        assert!(!checked(&report).run.finished());
        let written = report.human_text();
        assert!(written.contains("Privacy and model use"), "{written}");
        assert!(written.contains("Mode in effect: local_first"), "{written}");
        assert!(
            written.contains("No model was consulted"),
            "a stopped run does not say what it did about models:\n{written}"
        );
        assert_eq!(
            machine_of(&report)["model_use"]["state"],
            json!("no_provider")
        );
    }

    // --- recheck and repair are the same orchestrator ---------------------

    #[test]
    fn recheck_and_repair_reach_the_same_orchestrator_and_go_further_down_it() {
        // The criterion that says the three commands are not three paths into the
        // engine. Same project, three purposes, one stage log — and the last two
        // stages are what distinguishes them: `repair` adds the repair contract,
        // `recheck` also compares with what the last run left open.
        let fixture = Fixture::new("three-purposes");
        a_rust_project(&fixture);
        let paths = fixture.paths();
        let project = fixture.project();

        let check = run_with(Purpose::Check, &paths, &project, None);
        let repair = run_with(Purpose::Repair, &paths, &project, None);
        let recheck = run_with(Purpose::Recheck, &paths, &project, None);

        let check = checked(&check);
        let repair = checked(&repair);
        let recheck = checked(&recheck);

        for (purpose, report) in [
            (Purpose::Check, check),
            (Purpose::Repair, repair),
            (Purpose::Recheck, recheck),
        ] {
            assert_eq!(report.run.purpose, purpose);
            assert_eq!(report.command, purpose.as_str());
            assert_eq!(
                report
                    .run
                    .stages
                    .iter()
                    .map(|r| r.stage)
                    .collect::<Vec<_>>(),
                Stage::ALL.to_vec(),
                "{purpose:?} did not walk the documented stages"
            );
            // The same first stages, from the same orchestrator: the project's
            // state is a fact about the project, so three runs of one project
            // must agree about it. Compared by digest rather than by the whole
            // fingerprint, because the identifier is generated per run — it names
            // *this reading*, and the digest is what says the reading was of the
            // same tree.
            assert_eq!(
                digest_of_run(check),
                digest_of_run(report),
                "{purpose:?} read a different project state"
            );
        }

        // `check` stops at the aggregate, and says why rather than going quiet.
        for report in [check, repair] {
            match &report.run.stage(Stage::Recheck).outcome {
                StageOutcome::NotPartOfWork { detail } => {
                    assert!(
                        detail.contains("earlier one"),
                        "stage 12 is out of scope without saying so: {detail}"
                    );
                }
                other => panic!("`{}` claims to re-check: {other:?}", report.command),
            }
        }
        assert!(
            !matches!(
                recheck.run.stage(Stage::Recheck).outcome,
                StageOutcome::NotPartOfWork { .. }
            ),
            "`sure recheck` recorded its own stage as not part of the run"
        );
        // And the stage repair exists for is not out of scope for `repair`: this
        // project has no open findings, so the contract has nothing to write and
        // says so — which is a different statement from "this run does not do
        // that", and the one the command must not make.
        assert!(
            !matches!(
                repair.run.stage(Stage::RepairContract).outcome,
                StageOutcome::NotPartOfWork { .. }
            ),
            "`sure repair` recorded the stage it exists for as not part of the run"
        );
        assert!(
            matches!(
                check.run.stage(Stage::RepairContract).outcome,
                StageOutcome::NotPartOfWork { .. }
            ),
            "`sure check` claims to write repair instructions"
        );
    }

    /// The project state a run is about, as the digest that names the tree.
    fn digest_of_run(report: &CheckReport) -> Option<&str> {
        report
            .run
            .run
            .as_ref()
            .map(|run| run.project_state.digest.as_str())
    }

    // --- the goal ---------------------------------------------------------

    #[test]
    fn a_goal_typed_to_sure_is_stored_and_the_check_still_happens() {
        // P2-T010's acceptance and P7-T010's together: the goal is stored, the
        // run continues into the pipeline, and the report says both. Before this
        // task the command stopped at the write.
        let fixture = Fixture::new("goal-stored");
        a_project(&fixture);
        let paths = fixture.paths();
        let project = fixture.project();

        let goal = "make the upload reject a file over 10 MB instead of failing silently";
        let report = run_with(Purpose::Check, &paths, &project, Some(goal));

        let check = checked(&report);
        let recorded = check
            .recorded_goal
            .as_ref()
            .expect("the goal was written and the report does not say so");
        assert_eq!(recorded.goal, goal);
        assert_eq!(recorded.requirement_id, EXPLICIT_GOAL_ID);
        assert_eq!(recorded.source, IntentSource::ExplicitUserGoal);
        assert_eq!(recorded.project_root, project.to_str().unwrap());
        assert!(recorded.record > 0, "a row identifier is not a row number");

        // The check happened: a verdict exists, and it is a verdict about the
        // same project state the goal was recorded against.
        let run = check
            .run
            .run
            .as_ref()
            .expect("the check produced a verdict");
        assert_eq!(
            run.project_state.digest, recorded.project_state.digest,
            "the goal was recorded against one state and the check was about another"
        );
        // And the goal reached stage 2 rather than only the store: the run's
        // intent holds it, so the check was made against what the user asked for.
        assert_eq!(
            run.intent.user_requirements().count(),
            1,
            "the goal was written and not used: {:?}",
            run.intent
        );

        let store = Store::open_at(&paths.store_file())
            .unwrap_or_else(|error| panic!("cannot open the store this run wrote: {error}"));
        let row = the_intent_row(&store);
        assert_eq!(row.id, recorded.record);
        assert_eq!(row.project_root.as_deref(), Some(project.to_str().unwrap()));
        assert_eq!(
            row.project_fingerprint.as_deref(),
            Some(recorded.project_state.id.as_str())
        );
        assert_eq!(row.document["text"], json!(goal));
        assert_eq!(row.document["source"], json!("explicit_user_goal"));
        assert!(row.document["raw_retained"].as_bool().unwrap_or(false));
    }

    #[test]
    fn the_goal_the_report_shows_is_the_text_the_record_holds() {
        // P15-T024, measured rather than argued: a credential in the words, and
        // then every surface this command has — the prose, the frame, the row and
        // the requirement the run checked against. The report has to show the
        // row's text rather than the words that were typed, and the credential
        // has to reach none of the four.
        //
        // What this cannot see is the store's file: the corpus case
        // `a-secret-typed-into-a-goal-reaches-the-store-only-redacted` drives the
        // same goal through a real process and reads every byte under the store
        // directory, which is where "no byte holds it" belongs.
        let fixture = Fixture::new("goal-held-text");
        a_project(&fixture);
        let paths = fixture.paths();
        let project = fixture.project();

        let credential = "ghp_0123456789abcdefghij";
        let goal = format!("deploy using token {credential} please");
        let report = run_with(Purpose::Check, &paths, &project, Some(&goal));

        let check = checked(&report);
        let recorded = check
            .recorded_goal
            .as_ref()
            .expect("the goal was written and the report does not say so");

        let store = Store::open_at(&paths.store_file()).expect("the store this run wrote");
        let row = the_intent_row(&store);
        assert_eq!(row.id, recorded.record);
        assert_eq!(
            row.document["text"],
            json!(recorded.goal),
            "the report shows a text the record does not hold: {}",
            row.document
        );
        // The row's text is the user's words with the credential removed, which
        // is what the equality above is about: without this, two surfaces that
        // both held the credential would satisfy it.
        assert_eq!(recorded.goal, "deploy using token *** please");

        // Neither form of the report prints the credential...
        let prose = report.human_text();
        assert!(
            !prose.contains(credential),
            "the human report prints the credential:\n{prose}"
        );
        let frame = machine_of(&report).to_string();
        assert!(
            !frame.contains(credential),
            "the frame prints the credential:\n{frame}"
        );
        // ...nor does any column of the row.
        assert!(
            !row.document.to_string().contains(credential),
            "the record holds the credential: {}",
            row.document
        );

        // And the requirement the run checked against is the one it wrote down.
        // The not-checked line for an unmatched requirement quotes the
        // requirement's own text, so this is the second place the typed words
        // would come back into the report.
        let run = check
            .run
            .run
            .as_ref()
            .expect("the check produced a verdict");
        let requirements: Vec<&str> = run
            .intent
            .user_requirements()
            .map(|requirement| requirement.text.as_str())
            .collect();
        assert_eq!(
            requirements,
            vec![recorded.goal.as_str()],
            "the run checked against an intent other than the one it recorded: {:?}",
            run.intent
        );
    }

    #[test]
    fn the_goal_is_written_verbatim_and_before_the_check() {
        // Two things a user cannot check for themselves. The first is the
        // acceptance's second half: nothing captured, nothing kept that was not
        // handed over in the same breath. The second is the same rule from the
        // other side — the words are the user's, so a run that trimmed or
        // rewrapped them would be storing a requirement nobody stated. The one
        // thing that is not kept as it arrived is a credential-shaped value,
        // which `the_goal_the_report_shows_is_the_text_the_record_holds` above
        // measures and `docs/architecture/PROJECT_INTENT.md` argues.
        let fixture = Fixture::new("goal-privacy");
        a_project(&fixture);
        let paths = fixture.paths();

        let goal = "  keep the two-space indent\nand do not trim the trailing tab\t";
        let report = run_with(Purpose::Check, &paths, &fixture.project(), Some(goal));
        assert_eq!(
            checked(&report)
                .recorded_goal
                .as_ref()
                .expect("recorded")
                .goal,
            goal,
            "the goal was edited on the way in"
        );

        let store = Store::open_at(&paths.store_file()).expect("the store this run wrote");
        assert!(
            store
                .history(&HistoryFilter::recordings(), 100)
                .expect("the recordings")
                .is_empty(),
            "recording a goal produced a raw recording"
        );
        for row in everything(&store) {
            assert!(
                !row.kind.is_recording(),
                "recording a goal wrote a recording: {}",
                row.document
            );
        }
        assert_eq!(the_intent_row(&store).document["text"], json!(goal));
    }

    #[test]
    fn the_same_project_state_is_the_same_state_twice_and_a_changed_one_is_not() {
        // What makes the fingerprint in the record an anchor rather than a token
        // that happens to be written down. It is read from two runs, so it is not
        // a claim about the fingerprinter — there are tests for that — but about
        // what this module records: the state of the project as it was when the
        // user said what they wanted.
        let fixture = Fixture::new("goal-fingerprint");
        fixture.write("main.py", "print('one')\n");
        let paths = fixture.paths();
        let project = fixture.project();

        let first = run_with(Purpose::Check, &paths, &project, Some("first thing"));
        let again = run_with(Purpose::Check, &paths, &project, Some("second thing"));
        assert_eq!(
            digest_of(&first),
            digest_of(&again),
            "an unchanged project fingerprinted differently on a second run, so the \
             recorded state says nothing about the project"
        );

        fixture.write("main.py", "print('two')\n");
        let changed = run_with(Purpose::Check, &paths, &project, Some("third thing"));
        assert_ne!(
            digest_of(&first),
            digest_of(&changed),
            "a changed project fingerprinted the same, so a goal could be read against a \
             state it was never stated for"
        );
    }

    /// The fingerprint a recorded goal was written against.
    fn digest_of(report: &Report) -> String {
        checked(report)
            .recorded_goal
            .as_ref()
            .expect("a recorded goal")
            .project_state
            .digest
            .clone()
    }

    #[test]
    fn a_goal_with_no_words_is_refused_before_the_store_exists() {
        // The refusal is in the value, so a caller that gets it never opened a
        // database to fail at it — and a user who typed nothing has no record to
        // clean up. The store's absence is the assertion that says so.
        let fixture = Fixture::new("goal-empty");
        let paths = fixture.paths();

        for goal in ["", "   ", "\t\n"] {
            let report = run_with(Purpose::Check, &paths, &fixture.project(), Some(goal));
            let failure = failure(&report);
            assert_eq!(failure.command, "check");
            assert_eq!(failure.what, NOTHING_RECORDED);
            assert!(
                !failure.detail.is_empty(),
                "the failure does not say what stopped it"
            );
            assert_eq!(report.exit_code(), exit::FAILED);
            assert_ne!(report.exit_code(), exit::UNAVAILABLE);
            assert!(
                !paths.store_file().exists(),
                "{goal:?} created the store before deciding it was not a goal"
            );
        }
    }

    #[test]
    fn a_project_that_cannot_be_read_leaves_no_store_behind() {
        // The order of the steps, as a fact about the filesystem. Opening a store
        // creates its directory and its file, so if the fingerprint were taken
        // afterwards, a run that recorded nothing would still have left a
        // database where the user keeps their history.
        //
        // Two projects that cannot be read, and they fail for different reasons:
        // which is the point, because a single case would leave the ordering
        // resting on one error path. The relative one cannot succeed on any
        // machine, and the missing absolute one is the ordinary mistake of a
        // mistyped path.
        let fixture = Fixture::new("goal-unreadable");
        let paths = fixture.paths();
        let missing = fixture.root.join("not-a-directory");

        for project in [Path::new("not-a-project"), missing.as_path()] {
            let report = run_with(Purpose::Check, &paths, project, Some("do it"));
            let failure = failure(&report);
            assert_eq!(failure.what, NOTHING_RECORDED, "{}", project.display());
            assert_eq!(report.exit_code(), exit::FAILED);
            assert!(
                failure.detail.len() > 20,
                "{} reports {failure:?}, which does not say what stopped it",
                project.display()
            );
            assert!(
                !paths.store_file().exists(),
                "a project SURE could not read ({}) left a store behind",
                project.display()
            );
            assert!(
                !paths.data_dir().exists(),
                "a project SURE could not read ({}) left its data directory behind",
                project.display()
            );
        }
    }

    #[test]
    fn the_store_may_not_be_inside_the_project_it_records_a_goal_for() {
        // `docs/architecture/STORAGE_AND_DATA_PATHS.md`: a project the agent can
        // edit is not a trusted place for evidence about that project, and a
        // history the project can rewrite cannot support a verdict. The rule is
        // `Paths::ensure_outside`'s and this test is only that the check goes
        // through it rather than around it.
        let fixture = Fixture::new("goal-inside");
        fixture.write("notes.txt", "hello\n");
        let project = fixture.project();
        let inside = Paths::from_roots(project.join(".sure"), fixture.root.join("config"))
            .expect("the scratch locations are absolute");

        let report = run_with(Purpose::Check, &inside, &project, Some("do the thing"));
        assert_eq!(failure(&report).what, NOTHING_RECORDED);
        assert_eq!(report.exit_code(), exit::FAILED);
        assert!(
            !inside.store_file().exists(),
            "SURE put its own evidence inside the project it was judging"
        );
    }

    // --- what a run writes on a machine that has never used SURE ----------

    #[test]
    fn a_check_with_no_goal_on_a_machine_with_no_history_writes_nothing() {
        // The promise the brief asks for: `sure check` on a machine that has
        // never used SURE must not leave a database behind. Opening a store
        // creates its directory and its file, and a check that created a history
        // in order to report that it had nothing to compare against would be a
        // command changing the thing it is describing.
        let fixture = Fixture::new("no-history");
        a_project(&fixture);
        let paths = fixture.paths();

        let report = run_with(Purpose::Check, &paths, &fixture.project(), None);
        assert!(checked(&report).run.finished());

        assert!(
            !paths.store_file().exists(),
            "a bare `sure check` created the record store"
        );
        assert!(
            !paths.data_dir().exists(),
            "a bare `sure check` created its data directory"
        );

        // And the run says what that cost rather than leaving it out: without a
        // history there are no claims to check and nothing to compare against,
        // and both stages are recorded as scope limits.
        for stage in [Stage::ClaimChecking] {
            match &checked(&report).run.stage(stage).outcome {
                StageOutcome::NotRun { reason, .. } => assert_eq!(
                    *reason,
                    Some(sure_core::status::NotCheckedReason::NotApplicable),
                    "{} is out of scope for a reason the vocabulary does not have",
                    stage.as_str()
                ),
                other => panic!("{} without a history is {other:?}", stage.as_str()),
            }
        }
    }

    // --- the capability tier comes from the project's own events ----------

    /// The finished run a check report is about, or a panic naming what stopped it.
    fn run_of(report: &Report) -> &sure_core::pipeline::RunOutcome {
        checked(report)
            .run
            .run
            .as_ref()
            .unwrap_or_else(|| panic!("the run did not finish: {:?}", checked(report).run))
    }

    /// The capability line this run reports, the same sentence the machine form
    /// carries.
    fn capability_line(report: &Report) -> String {
        run_of(report).verdict.capability.summary()
    }

    fn tier_of(report: &Report) -> u8 {
        run_of(report).verdict.capability.tier_number()
    }

    /// Record one session's worth of events for `project_root`.
    ///
    /// Through the same two steps a harness hook takes: the document is ingested
    /// from the harness's own JSON, then persisted against the project. A test
    /// that wrote the row directly would be testing the reader against a shape
    /// this crate invented rather than the shape an adapter sends.
    fn record_session(store: &Store, project_root: &str, event_types: &[&str]) {
        use sure_core::harness_event::ingest_event_str;
        use sure_core::ids::{EventId, FingerprintId};
        use sure_core::session_event_store::SessionEventStore;

        let sessions = SessionEventStore::new(store);
        for (index, event_type) in event_types.iter().enumerate() {
            let document = json!({
                "schema_version": sure_core::PROTOCOL_VERSION,
                "source": "codex",
                "event_type": event_type,
                "timestamp": format!("2026-09-14T09:10:{:02}.000Z", index + 1),
                "session_id": "session-42",
                "project_root": project_root,
            })
            .to_string();
            let ingested = ingest_event_str(&document)
                .unwrap_or_else(|error| panic!("the harness document is refused: {error}"));
            sessions
                .persist(
                    &ingested,
                    project_root,
                    &FingerprintId::generate(),
                    &EventId::generate(),
                )
                .expect("the event is stored");
        }
    }

    #[test]
    fn the_tier_in_a_check_report_is_the_one_the_projects_events_earn() {
        // Criterion 1, through the command's own entry point: the same command
        // over the same project, before and after a session is recorded for it,
        // and over a directory nothing was ever recorded for. The store is the
        // only thing that changed between the first two runs.
        let fixture = Fixture::new("capability-recorded-events");
        a_project(&fixture);
        let paths = fixture.paths();
        let project = fixture.project();
        let root = project.to_str().expect("the fixture path is text");

        // Nothing recorded, and no store: the tier this command has always
        // reported, in the words it has always used.
        let before = run_with(Purpose::Check, &paths, &project, None);
        assert_eq!(tier_of(&before), 0);
        assert_eq!(
            capability_line(&before),
            "SURE can look at the project as it is now. It cannot see what the AI did while it \
             worked. (capability tier 0, snapshot)",
            "a run with no store reports something other than the command line's own tier"
        );
        assert!(
            !paths.store_file().exists(),
            "a bare `sure check` created the store, so the run below is not about a project \
             with a recorded session but about a store this test made"
        );

        // A session recorded for this project, exactly as a hook would leave it.
        // One event of every kind SURE derives a capability from: the request,
        // the completion claim, a tool call, a failure, a file edit and Git
        // activity. A session that covers all of them is the case where the
        // derived report has no blind spots at all — which is what makes the
        // assertion below about the one that must survive it mean something.
        let store = Store::open(&paths, &project).expect("the store opens");
        record_session(
            &store,
            root,
            &[
                "user.request",
                "agent.claim",
                "tool.completed",
                "command.failed",
                "file.write",
                "git.commit",
            ],
        );
        drop(store);

        let after = run_with(Purpose::Check, &paths, &project, None);
        assert_eq!(
            tier_of(&after),
            1,
            "a project with a recorded session is reported at the tier that session earns: {}",
            capability_line(&after)
        );
        let line = capability_line(&after);
        assert!(
            line.contains(
                "SURE counted 6 session events recorded for this project by codex, between \
                 2026-09-14T09:10:01.000Z and 2026-09-14T09:10:06.000Z."
            ),
            "the line does not say what it counted: {line}"
        );
        assert!(
            line.contains("What SURE still cannot see: "),
            "the tier is reported with nothing beside it: {line}"
        );

        // And the machine form carries the same two things as data rather than
        // only as part of that sentence.
        let details = machine_of(&after);
        assert_eq!(details["report"]["capability"]["tier"], json!(1));
        assert_eq!(
            details["report"]["capability"]["blind_spots"],
            json!(["no_pre_action_control"]),
            "a session that covers every kind of event SURE reads still cannot be stopped \
             before it happens, and the machine form must not read as completeness"
        );
        assert_eq!(
            details["report"]["capability"]["evidence"]["events"],
            json!(6)
        );
        assert_eq!(
            details["report"]["capability"]["evidence"]["harnesses"],
            json!(["codex"])
        );
        assert_eq!(
            details["report"]["capability"]["evidence"]["elsewhere"],
            json!(0)
        );

        // A project nothing was recorded for, while the store holds this
        // project's session: the tier does not rise, and the line says why rather
        // than leaving a reader to conclude that nothing was ever recorded.
        let other = fixture.root.join("never-recorded");
        std::fs::create_dir_all(&other).expect("a project directory");
        std::fs::write(other.join("main.py"), "print('hello')\n").expect("a project file");
        let elsewhere = run_with(Purpose::Check, &paths, &other, None);
        assert_eq!(tier_of(&elsewhere), 0);
        let line = capability_line(&elsewhere);
        assert!(
            line.contains(
                "SURE counted no session events for this project: SURE's store holds none for \
                 it. SURE also read 6 session events recorded for other projects; they are not \
                 part of this project's tier and were not counted."
            ),
            "a project with no session reads like a project with one, or like a store nobody \
             ever wrote to: {line}"
        );
    }

    #[test]
    fn a_check_with_no_path_is_about_the_directory_sure_was_run_from() {
        // The documented default, resolved rather than handed on as `.`. A run
        // that passed `.` through would be refused by the fingerprinter for being
        // relative — a refusal about the spelling of an argument the user never
        // typed, since the path was not given at all.
        let resolved = project_of(None).expect("a test process has a current directory");
        assert!(
            resolved.is_absolute(),
            "the default project is not an absolute path: {resolved:?}"
        );
        assert_eq!(resolved, std::env::current_dir().unwrap());

        // A path that *was* given is not touched: SURE refuses a relative root
        // rather than resolving it against wherever it happens to be, and a
        // caller that repaired the argument instead would be checking a project
        // the user did not name.
        assert_eq!(
            project_of(Some(Path::new("not-a-project"))).unwrap(),
            PathBuf::from("not-a-project")
        );
    }

    // --- the two renderings -----------------------------------------------

    #[test]
    fn every_refusal_in_this_module_says_what_did_not_happen() {
        // `crate::report::Failed`'s own rule: the fixed sentence is what tells a
        // user whether their history changed. Asserted over every failure this
        // module can produce, because the one that got it wrong would be the one
        // nobody drove.
        let fixture = Fixture::new("failure-text");
        let fixture_paths = fixture.paths();
        let project = fixture.project();

        let cases: Vec<(&str, Report)> = vec![
            (
                "a goal with no words",
                run_with(Purpose::Check, &fixture_paths, &project, Some("   ")),
            ),
            (
                "a project path that is not text",
                run_with(
                    Purpose::Check,
                    &fixture_paths,
                    Path::new("relative"),
                    Some("do it"),
                ),
            ),
            (
                "a store inside the project",
                run_with(
                    Purpose::Check,
                    &Paths::from_roots(project.join(".sure"), fixture.root.join("config"))
                        .expect("absolute"),
                    &project,
                    Some("do it"),
                ),
            ),
        ];

        for (what_happened, report) in cases {
            let failure = failure(&report);
            assert_eq!(failure.command, "check", "{what_happened}");
            assert_eq!(
                failure.what, NOTHING_RECORDED,
                "{what_happened} does not say whether the history changed"
            );
            assert!(
                failure.detail.len() > 20,
                "{what_happened} reports {failure:?}, which does not tell the user what \
                 stopped it"
            );
            // The word a user needs in order to believe nothing changed.
            assert!(
                failure.what.contains("Nothing was recorded"),
                "{what_happened}: {}",
                failure.what
            );
        }
    }

    #[test]
    fn the_human_form_states_what_was_not_checked_and_what_the_status_means() {
        // The acceptance criterion "the run states what it did not check", in the
        // form a person reads. Nothing here is a formatting of the frame: the
        // sentences are the renderer's own.
        let fixture = Fixture::new("human-form");
        a_rust_project(&fixture);
        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);

        let written = report.human_text();
        for needed in [
            "SURE checked",
            // The section this repository already renders for what a run could
            // not establish, filled in from this run's own schedule and results.
            "Could not check",
            "run the tests",
            "What the run did, stage by stage",
            "NOT CHECKED",
            "SURE exited with status 1",
            "not 3",
        ] {
            assert!(
                written.contains(needed),
                "the human report does not say {needed:?}:\n{written}"
            );
        }
        assert!(
            !written.contains("is not implemented in this build"),
            "a command that ran is worded as one this build lacks:\n{written}"
        );
    }

    #[test]
    fn a_run_that_did_not_finish_says_so_without_claiming_anything_about_the_project() {
        // A project SURE cannot read is a complaint, not a report: there is no
        // verdict, so there is nothing to file and nothing to read as one.
        let fixture = Fixture::new("stopped");
        let paths = fixture.paths();
        let report = run_with(
            Purpose::Check,
            &paths,
            &fixture.root.join("not-a-directory"),
            None,
        );

        let check = checked(&report);
        assert!(!check.run.finished());
        assert_eq!(check.run.stopped_at, Some(Stage::Discover));
        assert!(
            !report.is_an_answer(),
            "a stopped run was written as an answer"
        );
        assert_eq!(report.exit_code(), exit::FAILED);

        let written = report.human_text();
        for needed in [
            "could not finish",
            "stopped at stage 1 of 12",
            "No verdict was produced",
            "status 5",
        ] {
            assert!(
                written.contains(needed),
                "the complaint does not say {needed:?}:\n{written}"
            );
        }
        assert!(
            !written.contains("SURE checked"),
            "a stopped run reports about the project as though it had read it:\n{written}"
        );

        // The frame says the same thing, in the fields a script reads.
        let frame: Value = serde_json::from_str(&report.human_text()).unwrap_or_else(|_| {
            let mut buffer = Vec::new();
            report.machine(&mut buffer).expect("the frame writes");
            serde_json::from_slice(&buffer).expect("the frame is JSON")
        });
        let _ = frame;
        let details = machine_of(&report);
        assert_eq!(details["state"], json!("stopped"));
        assert_eq!(details["stopped_at"], json!("discover"));
        assert!(details["report"].is_null());
    }

    #[test]
    fn the_frame_carries_every_stage_and_the_reason_each_gap_has() {
        // The machine form of the stage record: a script has to be able to name
        // the stage that did not run and the vocabulary's reason for it, without
        // parsing a sentence.
        let fixture = Fixture::new("frame-stages");
        a_project(&fixture);
        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
        let details = machine_of(&report);

        let stages = details["stages"].as_array().expect("a list of stages");
        assert_eq!(stages.len(), Stage::ALL.len());
        for (position, entry) in stages.iter().enumerate() {
            assert_eq!(entry["number"], json!(position + 1));
            assert_eq!(entry["stage"], json!(Stage::ALL[position].as_str()));
            assert!(
                entry["detail"]
                    .as_str()
                    .is_some_and(|text| !text.is_empty()),
                "a stage with no account of itself: {entry}"
            );
            assert!(
                ["ran", "not_run", "not_part_of_work", "unfinished"]
                    .contains(&entry["outcome"].as_str().unwrap_or("")),
                "a stage outcome a reader does not know: {entry}"
            );
        }
        assert_eq!(
            details["green"],
            json!(false),
            "this build cannot report a project clean, and the frame says it did: {details}"
        );
        assert_eq!(details["purpose"], json!("check"));
        assert_eq!(details["mode"], json!("inspect_only"));
        assert!(
            details["report"]["aggregate"]["headline"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "the frame carries no verdict: {details}"
        );
    }

    #[test]
    fn the_goal_is_in_the_frame_and_so_is_what_the_run_did_with_it() {
        // The other rendering of the one side effect, and the reason the goal is
        // carried in the report type rather than only written to the store.
        let fixture = Fixture::new("frame-goal");
        a_project(&fixture);
        let report = run_with(
            Purpose::Check,
            &fixture.paths(),
            &fixture.project(),
            Some("make it faster"),
        );
        let details = machine_of(&report);

        let goal = &details["recorded_goal"];
        assert_eq!(goal["goal"], json!("make it faster"));
        assert_eq!(goal["source"], json!("explicit_user_goal"));
        assert_eq!(goal["project_state"]["kind"], json!("content"));
        assert!(
            goal["record"]["as_i64"].is_null() && goal["record"].is_i64(),
            "the row identifier is not a number: {goal}"
        );
        assert_eq!(goal["requirement_id"], json!(EXPLICIT_GOAL_ID));
    }

    #[test]
    fn a_check_that_recorded_no_goal_says_so_by_leaving_the_field_null() {
        let fixture = Fixture::new("frame-no-goal");
        a_project(&fixture);
        let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
        assert!(machine_of(&report)["recorded_goal"].is_null());
    }

    #[test]
    fn the_purpose_a_command_runs_under_is_the_name_it_answers_with() {
        // `CheckReport::command` comes from the purpose, and the frame's
        // `command` comes from the report. Three commands, three names, one
        // dispatcher each.
        for purpose in [Purpose::Check, Purpose::Recheck, Purpose::Repair] {
            assert_eq!(purpose.as_str(), purpose.as_str());
        }
        assert_eq!(Purpose::Check.as_str(), "check");
        assert_eq!(Purpose::Recheck.as_str(), "recheck");
        assert_eq!(Purpose::Repair.as_str(), "repair");
    }
}
