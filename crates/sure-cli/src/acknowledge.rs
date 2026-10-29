//! `sure acknowledge`: a person's recorded decision to live with a finding
//! (ADR 0019).
//!
//! # What this module is
//!
//! The three-ended surface of one record: `--finding … --reason …` writes an
//! acceptance, `--list` shows the ones this project has, `--undo` removes one.
//! The record itself, its identity rule and its refusals are
//! [`sure_core::acknowledgement`]'s; this module resolves the things only a
//! command line has — which project, which recorded finding, which store — and
//! hands the answer back as a [`Report`] the two renderers can write.
//!
//! # Why the store has to exist already — except when the caller brings the
//! finding
//!
//! `sure check` opens a store only when its file is already there
//! (`crate::check`'s module comment), because a command that created a store to
//! report what it recorded would be changing the thing it describes. This
//! command reads that store for `--finding` without `--from`, `--list` and
//! `--undo`: a machine with no history has no recorded finding to look up, and
//! creating a store to answer "no finding with that id" would leave a database
//! behind for a question nobody asked it.
//!
//! The `--from` form is the other side: a plain `sure check` records nothing,
//! so the id a person sees lives only in the report it printed, and that report
//! carries the finding's identity and the run's own `acknowledgeable` answer.
//! That form brings its own finding, so it is a legitimate first write and may
//! create the store.
//!
//! # Why the finding is looked up by id
//!
//! The id is what `sure check` printed; a person copies it. The lookup is the
//! store's own history for this project — the rows a re-check already reads —
//! so an id from last week's report still resolves, and the same path spells one
//! project here as it does there ([`same_project_root`]).
//!
//! # What this command never does
//!
//! It never accepts a finding the evidence settled. A failing test, a checker
//! error and a check that did not run are refused with the domain's own
//! sentence ([`AcknowledgementError`]), because those are defects and gaps to
//! fix, and recording them as accepted risks would turn the verdict into the
//! user's opinion of the project.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sure_core::acknowledgement::{self, AcknowledgementError, ReportedFinding};
use sure_core::diagnostics::Timestamp;
use sure_core::finding::Finding;
use sure_core::ids::FingerprintId;
use sure_core::paths::Paths;
use sure_core::recheck_lifecycle::{HISTORY_SCAN_LIMIT, case_rule_for, same_project_root};
use sure_core::store::{DocumentKind, HistoryFilter, RecordKind, Store};

use crate::commands::Named;
use crate::report::{Failed, Report};

/// What `sure acknowledge` did, as a value both renderers write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcknowledgeReport {
    /// The project the answer is about, as the command resolved it.
    pub project: String,
    /// The one thing that happened.
    pub action: AcknowledgeAction,
}

/// The three things `sure acknowledge` can answer with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcknowledgeAction {
    /// A decision was recorded.
    Recorded(RecordedAcknowledgement),
    /// What this project has accepted, newest first.
    Listed(Vec<RecordedAcknowledgement>),
    /// One record was, or was not, removed.
    Removed {
        /// The row id the caller named.
        record: i64,
        /// Whether a row went.
        removed: bool,
    },
}

/// One acceptance, as the report shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedAcknowledgement {
    /// The store row, which `--undo` takes.
    pub record: i64,
    /// The finding id the decision was made from.
    pub finding_id: String,
    /// The finding's title.
    pub title: String,
    /// Where the evidence is.
    pub location: String,
    /// What the evidence is.
    pub locator: String,
    /// Why the person accepted it.
    pub reason: String,
    /// When, in milliseconds since the epoch.
    pub recorded_at_ms: i64,
}

/// What a command line asked for; the grammar has already refused two at once.
enum Asked<'a> {
    Record {
        finding: &'a str,
        from: Option<&'a Path>,
        reason: &'a str,
    },
    List,
    Undo(i64),
}

/// Run one `sure acknowledge` invocation.
#[must_use]
pub fn run(
    project: Option<&Path>,
    finding: Option<&str>,
    from: Option<&Path>,
    reason: Option<&str>,
    list: bool,
    undo: Option<i64>,
    named: Named<'_>,
) -> Report {
    let asked = match (finding, list, undo) {
        (Some(finding), _, _) => Asked::Record {
            finding,
            from,
            reason: reason.unwrap_or(""),
        },
        (None, true, _) => Asked::List,
        (None, false, Some(record)) => Asked::Undo(record),
        // The grammar requires exactly one action, so this arm is a build that
        // disagrees with its own clap definition rather than a user error; it
        // still answers rather than panics.
        (None, false, None) => {
            return failed("nothing was asked for: name --finding, --list or --undo");
        }
    };

    let root = match project_of(project) {
        Ok(root) => root,
        Err(detail) => return failed(&detail),
    };
    let paths = match Paths::discover_with(named.store, named.settings_file) {
        Ok(paths) => paths,
        Err(error) => return failed(&error.to_string()),
    };
    // The store must be there for every form that *reads* it. The `--from` form
    // writes and brings its own finding, so it may create the store — an
    // acceptance recorded before any run was recorded is a legitimate first
    // write, and the sentence below would otherwise tell a person to run a
    // command that does not record anything.
    let creates = matches!(&asked, Asked::Record { from: Some(_), .. });
    if !creates && !paths.store_file().is_file() {
        return failed(
            "SURE has no recorded history on this machine, so there is no finding to accept. \
             Write the report with `sure check --format json > report.json` and name it with \
             `--from`, or run `sure repair`, which records what it finds, and acknowledge from \
             there.",
        );
    }
    let store = match Store::open(&paths, &root) {
        Ok(store) => store,
        Err(error) => return failed(&error.to_string()),
    };
    let project = root.to_string_lossy().into_owned();

    let action = match asked {
        Asked::List => match acknowledgement::recorded(&store, &project) {
            Ok(records) => AcknowledgeAction::Listed(records.into_iter().map(shown).collect()),
            Err(error) => return failed(&error.to_string()),
        },
        Asked::Undo(record) => match acknowledgement::undo(&store, &project, record) {
            Ok(removed) => AcknowledgeAction::Removed { record, removed },
            Err(error) => return failed(&error.to_string()),
        },
        Asked::Record {
            finding,
            from,
            reason,
        } => match from {
            Some(report) => match record_from_report(&store, &project, report, finding, reason) {
                Ok(recorded) => AcknowledgeAction::Recorded(recorded),
                Err(detail) => return failed(&detail),
            },
            None => {
                let recorded = match find_recorded_finding(&store, &project, finding) {
                    Ok(Some(recorded)) => recorded,
                    Ok(None) => {
                        return failed(&format!(
                            "SURE's history holds no finding with the id `{finding}` for this \
                             project. A plain `sure check` records nothing, so name the report the \
                             id was printed by with `--from FILE` (written with `sure check \
                             --format json > FILE`), or run `sure repair`, which records what it \
                             finds, and acknowledge from there."
                        ));
                    }
                    Err(error) => return failed(&error.to_string()),
                };
                let case = case_rule_for(&project);
                match acknowledgement::acknowledge(
                    &store,
                    &project,
                    &recorded.fingerprint,
                    &recorded,
                    reason,
                    case,
                ) {
                    Ok(stored) => AcknowledgeAction::Recorded(shown(stored)),
                    Err(error) => return failed(&error.to_string()),
                }
            }
        },
    };

    Report::Acknowledge(Box::new(AcknowledgeReport { project, action }))
}

/// The project this run is about: the one named, or the one SURE was run from.
///
/// `crate::check::project_of`'s rule, restated by the same words: `.` means
/// "wherever this process happens to be", and a record naming it can be read
/// later against a directory the user never meant.
fn project_of(project: Option<&Path>) -> Result<PathBuf, String> {
    match project {
        Some(path) => Ok(path.to_path_buf()),
        None => std::env::current_dir().map_err(|error| {
            format!(
                "SURE could not work out which directory it is running in, so it could not tell \
                 which project this is about. Name the project explicitly: {error}"
            )
        }),
    }
}

/// The newest recorded finding with this id that belongs to this project.
///
/// The same kind of read as a re-check's: history newest-first, filtered to this
/// project by [`same_project_root`] under the volume's case rule, decoded with
/// the store's own version check. A row that cannot be decoded stops the read
/// rather than being skipped — [`crate::check`]'s rule for the same rows.
fn find_recorded_finding(
    store: &Store,
    project: &str,
    id: &str,
) -> Result<Option<Finding>, AcknowledgementError> {
    let filter = HistoryFilter {
        project_fingerprint: None,
        kind: Some(RecordKind::Document(DocumentKind::Finding)),
        include_recordings: false,
    };
    let rows = store.history(&filter, HISTORY_SCAN_LIMIT)?;
    if rows.len() >= HISTORY_SCAN_LIMIT {
        return Err(AcknowledgementError::Store(
            sure_core::store::StoreError::MalformedRow {
                id: 0,
                message: format!(
                    "the history holds more than {HISTORY_SCAN_LIMIT} finding rows and the read \
                     stopped at that bound; the id was not looked up in a truncated list"
                ),
            },
        ));
    }
    let case = case_rule_for(project);
    for row in rows {
        if !row
            .project_root
            .as_deref()
            .is_some_and(|root| same_project_root(root, project, case))
        {
            continue;
        }
        let finding: Finding = row.decode()?;
        if finding.id.as_str() == id {
            return Ok(Some(finding));
        }
    }
    Ok(None)
}

/// Record an acceptance for a finding read out of a machine-form report.
///
/// A plain `sure check` records nothing — that is the documented contract
/// (`docs/architecture/CLI.md`, `--store-dir`) — so the id a person sees in its
/// report exists only in that report. This is the other way in: the report SURE
/// itself wrote names the finding's identity, the check that it may be accepted
/// (`acknowledgeable`, computed from the finding's own evidence) and the project
/// state it was found against, and the record is written from those values
/// rather than from anything typed. A report that says the finding is not
/// acknowledgeable is refused here, and a report that lies is caught again when
/// the acceptance is applied: the pipeline re-checks the finding it would mark.
fn record_from_report(
    store: &Store,
    project: &str,
    report: &Path,
    id: &str,
    reason: &str,
) -> Result<RecordedAcknowledgement, String> {
    let text = std::fs::read_to_string(report).map_err(|error| {
        format!(
            "SURE could not read the report {}: {error}",
            report.display()
        )
    })?;
    let document: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
        format!(
            "the file {} is not the one-object JSON `sure check --format json` writes: {error}",
            report.display()
        )
    })?;
    // The frame carries the report under `details.report`; a caller that saved
    // the report value on its own is read the same way.
    let body = document
        .get("details")
        .and_then(|details| details.get("report"))
        .unwrap_or(&document);
    let findings = body
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            format!(
                "the file {} holds no findings list. Write the report with `sure check --format \
                 json > report.json` and name that file.",
                report.display()
            )
        })?;
    let finding = findings
        .iter()
        .find(|finding| finding.get("id").and_then(serde_json::Value::as_str) == Some(id))
        .ok_or_else(|| {
            format!(
                "the report {} holds no finding with the id `{id}`. Copy the id from the report \
                 it was printed by.",
                report.display()
            )
        })?;
    if finding
        .get("acknowledgeable")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return Err(
            "SURE's report says this finding cannot be accepted. Its evidence is a check result \
             or a gap, not an inference, and those are defects to fix rather than risks to \
             accept."
                .to_owned(),
        );
    }
    let title = finding
        .get("title")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "the report's finding carries no title".to_owned())?;
    let anchor = finding
        .get("evidence_anchors")
        .and_then(serde_json::Value::as_array)
        .and_then(|anchors| {
            anchors.iter().find_map(|anchor| {
                let location = anchor.get("location")?.as_str()?;
                let locator = anchor.get("locator")?.as_str()?;
                Some((location, locator))
            })
        })
        .ok_or_else(|| {
            "the report's finding carries no checkable evidence anchor, so an acceptance could \
             not be bound to evidence that can change"
                .to_owned()
        })?;
    let fingerprint = body
        .get("project_fingerprint")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "the report names no project state".to_owned())?;
    let fingerprint = FingerprintId::parse(fingerprint)
        .map_err(|error| format!("the report's project state could not be read: {error}"))?;
    let reported = ReportedFinding {
        finding_id: id.to_owned(),
        title: title.to_owned(),
        location: anchor.0.to_owned(),
        locator: anchor.1.to_owned(),
    };
    acknowledgement::acknowledge_reported(
        store,
        project,
        &fingerprint,
        &reported,
        reason,
        case_rule_for(project),
    )
    .map(shown)
    .map_err(|error| error.to_string())
}

/// One stored acceptance, as the report shows it.
fn shown(recorded: acknowledgement::RecordedAcknowledgement) -> RecordedAcknowledgement {
    let a = recorded.acknowledgement;
    RecordedAcknowledgement {
        record: recorded.row,
        finding_id: a.finding_id,
        title: a.title,
        location: a.location,
        locator: a.locator,
        reason: a.reason,
        recorded_at_ms: a.recorded_at_ms,
    }
}

/// A command that tried and could not finish, under this command's own name.
fn failed(detail: &str) -> Report {
    Report::Failed(Box::new(Failed {
        command: "acknowledge",
        what: "nothing was recorded",
        detail: detail.to_owned(),
    }))
}

/// Write the human form.
///
/// # Errors
///
/// Any failure from `out`.
pub fn human(report: &AcknowledgeReport, out: &mut impl Write) -> io::Result<()> {
    match &report.action {
        AcknowledgeAction::Recorded(recorded) => {
            writeln!(out, "Accepted: {}", recorded.title)?;
            writeln!(out, "  at {}", evidence_of(recorded))?;
            writeln!(
                out,
                "This is recorded in your local history as record {} (the project itself cannot \
                 see or change it). The next check will report the finding as an accepted risk \
                 and will not count it against the project.",
                recorded.record
            )?;
            writeln!(
                out,
                "If the evidence at that location changes, the acceptance stops applying and \
                 the finding comes back for review."
            )?;
            writeln!(out, "Reason: {}", recorded.reason)
        }
        AcknowledgeAction::Listed(records) => {
            if records.is_empty() {
                writeln!(out, "Nothing has been accepted for {}.", report.project)?;
                return Ok(());
            }
            writeln!(out, "Accepted risks recorded for {}:", report.project)?;
            for recorded in records {
                writeln!(out, "  record {}", recorded.record)?;
                writeln!(out, "    finding: {}", recorded.title)?;
                writeln!(out, "    at:      {}", evidence_of(recorded))?;
                writeln!(
                    out,
                    "    decided: {}",
                    Timestamp::from_millis(recorded.recorded_at_ms)
                )?;
                writeln!(out, "    reason:  {}", recorded.reason)?;
            }
            Ok(())
        }
        AcknowledgeAction::Removed {
            record,
            removed: true,
        } => writeln!(
            out,
            "Removed record {record}. The finding it covered will be reported as unresolved \
             again on the next check."
        ),
        AcknowledgeAction::Removed {
            record,
            removed: false,
        } => writeln!(
            out,
            "No acknowledgement record {record} belongs to this project, so nothing was removed."
        ),
    }
}

/// The machine form of one report, under the frame's `details` key.
#[must_use]
pub fn machine(report: &AcknowledgeReport) -> serde_json::Value {
    let records = |list: &[RecordedAcknowledgement]| {
        list.iter()
            .map(|recorded| {
                serde_json::json!({
                    "record": recorded.record,
                    "finding_id": recorded.finding_id,
                    "title": recorded.title,
                    "location": recorded.location,
                    "locator": recorded.locator,
                    "reason": recorded.reason,
                    "recorded_at_ms": recorded.recorded_at_ms,
                })
            })
            .collect::<Vec<_>>()
    };
    match &report.action {
        AcknowledgeAction::Recorded(recorded) => serde_json::json!({
            "action": "recorded",
            "project": report.project,
            "record": recorded.record,
            "finding_id": recorded.finding_id,
            "title": recorded.title,
            "location": recorded.location,
            "locator": recorded.locator,
            "reason": recorded.reason,
            "recorded_at_ms": recorded.recorded_at_ms,
        }),
        AcknowledgeAction::Listed(list) => serde_json::json!({
            "action": "listed",
            "project": report.project,
            "records": records(list),
        }),
        AcknowledgeAction::Removed { record, removed } => serde_json::json!({
            "action": "removed",
            "project": report.project,
            "record": record,
            "removed": removed,
        }),
    }
}

/// The one line under a finding's title: where and what the evidence is.
fn evidence_of(recorded: &RecordedAcknowledgement) -> String {
    format!("{}: {}", recorded.location, recorded.locator)
}
