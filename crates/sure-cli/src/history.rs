//! `sure history`: what SURE has recorded on this machine, and how to be rid of
//! it.
//!
//! # What the user sees, and what they can do about it
//!
//! `docs/security/PRIVACY.md` asks for one thing of this command: "Users must be
//! able to inspect and delete local SURE history/recordings." The inspect half
//! is [`HistoryAction::List`] and [`HistoryAction::Show`]; the delete half is
//! [`HistoryAction::Delete`]. Both read and write the same rows, through
//! `sure_core::session_event_store`, and neither has a path of its own into
//! SQLite: the CLI owns the words, and the core owns what a session and an event
//! are.
//!
//! # Why the listing says what it does not know
//!
//! A session row carries `retention_days` and `retained_until_ms`, and **nothing
//! acts on them**: there is no pruning job in this build, and no caller of
//! `sessions_past_retention`, `events_past_retention`,
//! `full_recordings_past_retention` or `Store::delete_recordings` outside their
//! own tests. A listing that printed a deadline and stopped would leave a user
//! believing that a date in the past means the data is gone. It is not, and this
//! module says so in the output rather than in a document the user has not read.
//! Saying it there is also what keeps the sentence honest the day a pruning job
//! lands: it is one sentence, about this build, in one place.
//!
//! # Why a delete does not prompt
//!
//! `docs/architecture/CLI.md` left this decision to the command that needed it.
//! The answer is that **the scope on the command line is the consent**: exactly
//! one of `--all`, `--session ID` and `--project ROOT` is required, clap refuses
//! a command line with none or with two, and nothing is ever read from standard
//! input. A prompt is unusable from the harness integrations, which run SURE as a
//! subprocess; and a delete with no stated scope is worse, because the user
//! cannot see what it will do before it does it. Requiring the scope makes the
//! command line a description of the deletion, so it can be read in a script, in
//! a shell history, and in a bug report.
//!
//! # Why a failed delete cannot leave half a session
//!
//! The three tables are written in one transaction by
//! `SessionEventStore::delete_sessions`, which rolls back on any error. This
//! module never deletes row by row, and it never reports a count it did not get
//! back from the store: a delete whose scope matched nothing says so, in those
//! words, and a delete that failed is a [`Report::Failed`] with status 5.
//!
//! # Why nothing here is a claim about a project
//!
//! A history report says what is in the local store and what was removed from
//! it. It is not a verdict, it is not evidence about a project, and it changes no
//! verdict: `docs/architecture/CLI.md`'s "1 and 3 are never merged" is about
//! projects, and this command answers neither.

use std::io::{self, Write};
use std::path::Path;

use serde_json::{Value, json};
use sure_core::diagnostics::Timestamp;
use sure_core::hook_protection::Danger;
use sure_core::paths::Paths;
use sure_core::protection_history::{self, DecisionRecord};
use sure_core::redact::escape_control_characters;
use sure_core::session_event_store::{
    DeletedSessions, SessionEventStore, SessionScope, StoredEvent, StoredSession,
};
use sure_core::store::{Store, StoreError, StoredRecord};

use crate::cli::HistoryAction;
use crate::report::{Failed, NotYet, Report};

/// How many sessions `sure history` shows when the caller names no `--limit`.
///
/// One constant for the grammar's default and for the bare `sure history` that
/// reaches this module with no action at all, so the two cannot show different
/// numbers under the same command name.
pub const DEFAULT_LIMIT: u64 = 20;

/// The label column width, matching `crate::doctor`'s so that a user reading one
/// command's output after another sees one layout rather than two.
const LABEL: usize = 20;

/// What one `sure history` run found, or did.
///
/// The three subcommands share one type because they share one subject: the
/// store. `command` is the command the user typed, taken from the grammar rather
/// than retyped, so the frame names `history delete` for a delete — see
/// [`name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryReport {
    /// The command, as the user typed it: `history`, `history show`, …
    pub command: &'static str,
    /// Where the store is, whether or not it is there yet.
    ///
    /// On the report rather than looked up again by each renderer: a user asking
    /// "what has SURE recorded" is also asking "where", and one run cannot name
    /// two locations.
    pub store: String,
    /// Whether the store file exists.
    ///
    /// A store that is not there and a store with no rows in it are different
    /// answers — "nothing has ever been recorded" against "nothing is there now"
    /// — and they are reached by different code, so the distinction is carried
    /// rather than assumed.
    pub store_present: bool,
    /// What the run found or did.
    pub outcome: HistoryOutcome,
}

/// What a `sure history` run answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryOutcome {
    /// There is no store file: SURE has never recorded anything on this machine.
    NothingRecorded,
    /// The store was read and holds no session.
    NoSessions,
    /// Some sessions, newest first, and how many the store holds in total.
    Listed {
        /// The page of sessions, newest first.
        sessions: Vec<StoredSession>,
        /// How many sessions the store holds, whatever this page's size.
        total: u64,
        /// The page size the run was asked for.
        limit: u64,
    },
    /// One session, and the events recorded in it.
    Shown {
        /// The session row.
        session: Box<StoredSession>,
        /// Its events, newest first, each with the record it wrote if it wrote
        /// one.
        events: Vec<ShownEvent>,
    },
    /// A delete, and exactly what it removed.
    Deleted {
        /// What the scope was, in the words the user typed it with.
        scope: String,
        /// The rows that went, counted by table.
        deleted: DeletedSessions,
    },
}

/// One event, the record it wrote, and what SURE decided about it.
///
/// The one-event-per-event's-record pair rather than the event alone, because
/// `session_events.record_row_id` is a number a user cannot resolve, and a
/// listing of numbers nobody can look up is not an inspection surface. `None`
/// means the event owns no record.
///
/// `decision` is the third thing, and it is not the same thing as the record: the
/// record is the event as SURE stored it, and the decision is what SURE said
/// about it — the verdict, the danger, the sentence the user was shown, and
/// whether a one-time allowance bought it
/// (`sure_core::protection_history`). An event SURE reached no decision about
/// (anything that is not a tool request) has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShownEvent {
    /// The event row.
    pub event: StoredEvent,
    /// The `records` row this event owns, when there is one.
    pub record: Option<StoredRecord>,
    /// The protection decision SURE recorded about this event, when there is
    /// one.
    pub decision: Option<DecisionRecord>,
}

/// The name a user sees for a `sure history` invocation.
///
/// The subcommand is part of the name, and it has to be: a user who typed the
/// destructive one and is answered about the harmless one has been told the
/// wrong thing. Every arm is a literal, so nothing a project controls can reach
/// this string.
#[must_use]
pub fn name(action: Option<&HistoryAction>) -> &'static str {
    match action {
        None | Some(HistoryAction::List { .. }) => "history",
        Some(HistoryAction::Show { .. }) => "history show",
        Some(HistoryAction::Delete { .. }) => "history delete",
        Some(HistoryAction::Export) => "history export",
    }
}

/// `sure history`, resolving where SURE keeps its files.
///
/// `store` is the store directory the caller named on the command line, or
/// `None` for the platform's own per-user location. See
/// [`sure_core::paths::Paths::discover_at`].
///
/// # Errors
///
/// None: a failure is a [`Report::Failed`], because a command that could not
/// finish still has to answer in the shape a caller reads.
#[must_use]
pub fn run(action: Option<&HistoryAction>, store: Option<&Path>) -> Report {
    let command = name(action);
    let paths = match Paths::discover_at(store) {
        Ok(paths) => paths,
        Err(error) => {
            return failed(
                command,
                "SURE could not work out where its own files go.",
                error.to_string(),
            );
        }
    };

    match action {
        // A bare `sure history` is the listing. The grammar documents `list` as
        // the default, and this is where that is true rather than merely said.
        None => listing(command, &paths, DEFAULT_LIMIT),
        Some(HistoryAction::List { limit }) => listing(command, &paths, *limit),
        Some(HistoryAction::Show { id }) => showing(command, &paths, id),
        Some(HistoryAction::Delete {
            all,
            session,
            project,
        }) => deleting(
            command,
            &paths,
            *all,
            session.as_deref(),
            project.as_deref(),
        ),
        // The one `sure history` subcommand this build does not carry out.
        // `--format json` is the machine-readable form of every command on this
        // surface, and it is chosen in exactly one place (`crate::cli::Cli`);
        // an `export` that chose it again would be a second decision about
        // output, which is the thing that flag's documentation says cannot
        // exist. The refusal says what to type instead rather than leaving the
        // user to guess, and it is status 3: this build cannot carry it out.
        Some(HistoryAction::Export) => Report::Unavailable(NotYet {
            command: "history export",
            does: "write the history out as JSON",
            instead: "Use `sure --format json history`: the output format is chosen once, on \
                      the command line, and this subcommand would choose it a second time.",
        }),
    }
}

/// The store, when its file is already there.
///
/// **Never created.** A command whose job is to report what has been recorded
/// must not bring a store into existence in order to report that there is
/// nothing in it: the file it left behind is the evidence of a run that claimed
/// to have found nothing. `crate::check` has the same rule and for the same
/// reason.
///
/// # Errors
///
/// [`StoreError`] from opening a store that is there and cannot be read — a
/// damaged file, one written by a newer build, or one whose migration fails.
/// That is not "no history": it is a history SURE could not look at, and the
/// caller must not report the first while the second is true.
fn open_existing(paths: &Paths) -> Result<Option<Store>, StoreError> {
    if !paths.store_file().exists() {
        return Ok(None);
    }
    Store::open_at(&paths.store_file()).map(Some)
}

/// The store and what it holds, for a run that only reads.
fn listing(command: &'static str, paths: &Paths, limit: u64) -> Report {
    let store = match open_existing(paths) {
        Ok(store) => store,
        Err(error) => return store_failed(command, paths, error),
    };
    let Some(store) = store else {
        return Report::History(Box::new(HistoryReport {
            command,
            store: paths.store_file().display().to_string(),
            store_present: false,
            outcome: HistoryOutcome::NothingRecorded,
        }));
    };

    let sessions = SessionEventStore::new(&store);
    let page = match sessions.sessions(usize::try_from(limit).unwrap_or(usize::MAX)) {
        Ok(page) => page,
        Err(error) => return read_failed(command, error),
    };
    // Read separately from the page so that a listing which showed fewer rows
    // than there are can say how many there are. "20 of 340" is a different
    // sentence from "20", and a report that could only say the second would be
    // telling the user their history is smaller than it is.
    let total = match sessions.session_count() {
        Ok(total) => total,
        Err(error) => return read_failed(command, error),
    };

    let outcome = if total == 0 {
        HistoryOutcome::NoSessions
    } else {
        HistoryOutcome::Listed {
            sessions: page,
            total,
            limit,
        }
    };
    Report::History(Box::new(HistoryReport {
        command,
        store: store.path().display().to_string(),
        store_present: true,
        outcome,
    }))
}

/// One session and its events.
fn showing(command: &'static str, paths: &Paths, id: &str) -> Report {
    let store = match open_existing(paths) {
        Ok(store) => store,
        Err(error) => return store_failed(command, paths, error),
    };
    let Some(store) = store else {
        return no_such_session(command, paths, id, false);
    };

    let sessions = SessionEventStore::new(&store);
    let session = match sessions.session_by_sure_id(id) {
        Ok(Some(session)) => session,
        Ok(None) => return no_such_session(command, paths, id, true),
        Err(error) => return read_failed(command, error),
    };

    let rows = match sessions.events_for_session(session.row_id) {
        Ok(rows) => rows,
        Err(error) => return read_failed(command, error),
    };

    // The record an event owns, read through the store's own reader rather than
    // through a second query written here, which would be a second place for the
    // answer to be wrong. A record that cannot be read stops the whole listing:
    // a session shown without the record it wrote is a session with a hole in
    // it, and it would look complete.
    //
    // The decisions are read for the same reason and in one query for the whole
    // session rather than one per event: the verdict is the thing a reader came
    // for, and a listing that quietly left out one it could not read would be
    // the same hole in a different place.
    let decisions = match sessions.decisions_for_session(session.row_id) {
        Ok(rows) => rows,
        Err(error) => return read_failed(command, error),
    };

    let mut events = Vec::with_capacity(rows.len());
    for event in rows {
        let record = match event.record_row_id {
            None => None,
            Some(row) => match store.record(row) {
                Ok(record) => record,
                Err(error) => return record_unreadable(command, paths, error),
            },
        };
        let decision = decisions
            .iter()
            .find(|row| {
                row.document.get("event_id").and_then(Value::as_str)
                    == Some(event.event_id.as_str())
            })
            .cloned();
        let decision = match decision {
            None => None,
            Some(row) => match protection_history::read_back(row) {
                Ok(decision) => Some(decision),
                Err(error) => return record_unreadable(command, paths, error),
            },
        };
        events.push(ShownEvent {
            event,
            record,
            decision,
        });
    }

    Report::History(Box::new(HistoryReport {
        command,
        store: store.path().display().to_string(),
        store_present: true,
        outcome: HistoryOutcome::Shown {
            session: Box::new(session),
            events,
        },
    }))
}

/// What a `sure history delete` run did.
fn deleting(
    command: &'static str,
    paths: &Paths,
    all: bool,
    session: Option<&str>,
    project: Option<&str>,
) -> Report {
    let (scope, words) = match scope_of(all, session, project) {
        Ok(scope) => scope,
        // Reachable only from a hand-built [`HistoryAction`]: the grammar
        // requires exactly one scope, and clap refuses a command line without
        // one. It fails closed rather than falling through to `All`, because the
        // one thing this arm must never do is delete everything on a command
        // line that named nothing.
        Err(()) => {
            return failed(
                command,
                "Nothing was deleted.",
                "Exactly one of --all, --session and --project is required, and this \
                 invocation named none or more than one."
                    .to_owned(),
            );
        }
    };

    let store = match open_existing(paths) {
        Ok(store) => store,
        Err(error) => return store_failed(command, paths, error),
    };
    let Some(store) = store else {
        return Report::History(Box::new(HistoryReport {
            command,
            store: paths.store_file().display().to_string(),
            store_present: false,
            outcome: HistoryOutcome::Deleted {
                scope: words,
                deleted: DeletedSessions::default(),
            },
        }));
    };

    let sessions = SessionEventStore::new(&store);
    let deleted = match sessions.delete_sessions(scope) {
        Ok(deleted) => deleted,
        Err(error) => {
            return failed(
                command,
                "Nothing was deleted.",
                format!(
                    "The store at {} could not be changed: {}",
                    escape_control_characters(&store.path().display().to_string()),
                    error
                ),
            );
        }
    };

    Report::History(Box::new(HistoryReport {
        command,
        store: store.path().display().to_string(),
        store_present: true,
        outcome: HistoryOutcome::Deleted {
            scope: words,
            deleted,
        },
    }))
}

/// The scope a delete was asked for, and the words that name it.
///
/// One function for both, so that what the report says was deleted cannot be a
/// different scope from the one that was: the sentence is built from the same
/// arguments the [`SessionScope`] is.
///
/// `Err(())` for a combination the grammar does not produce — see the caller.
fn scope_of<'a>(
    all: bool,
    session: Option<&'a str>,
    project: Option<&'a str>,
) -> Result<(SessionScope<'a>, String), ()> {
    match (all, session, project) {
        (true, None, None) => Ok((SessionScope::All, "every session in this store".to_owned())),
        (false, Some(id), None) => Ok((
            SessionScope::One(id),
            format!(
                "the session with SURE session id {}",
                escape_control_characters(id)
            ),
        )),
        (false, None, Some(root)) => Ok((
            SessionScope::Project(root),
            format!(
                "every session recorded against {}",
                escape_control_characters(root)
            ),
        )),
        _ => Err(()),
    }
}

/// A session id that is not in the store.
///
/// Status 5 rather than 3 and rather than 1. Not 3: this build can show a
/// session, and it did look. Not 1: 1 says a project has problems, and this
/// command never looked at a project. What happened is that the command tried
/// and could not finish, which is what status 5 is for.
fn no_such_session(command: &'static str, paths: &Paths, id: &str, store_present: bool) -> Report {
    let where_it_looked = if store_present {
        format!("the store at {}", paths.store_file().display())
    } else {
        format!(
            "this machine, where SURE has never recorded anything (there is no {})",
            paths.store_file().display()
        )
    };
    failed(
        command,
        "Nothing was shown.",
        format!(
            "No session in {where_it_looked} has the id {}. Run `sure history` to list the ids \
             of the sessions that are there.",
            escape_control_characters(id)
        ),
    )
}

/// A store that is there and could not be read.
///
/// Deliberately not "there is no history": that would be a claim about a store
/// SURE never managed to open, and a user would stop looking.
fn store_failed(command: &'static str, paths: &Paths, error: StoreError) -> Report {
    failed(
        command,
        "Nothing was read from the history, and nothing was deleted.",
        format!(
            "SURE found a store at {} and could not open it: {}",
            escape_control_characters(&paths.store_file().display().to_string()),
            error
        ),
    )
}

/// A store that opened, and a record inside it that would not read back.
///
/// A sentence of its own rather than [`store_failed`]'s: the store opened, so
/// "could not open it" would be the wrong fact about a real problem, and the row
/// is what a user would have to look at. The store's own reader refuses to skip
/// a row it cannot describe, and this is that refusal reaching the user.
fn record_unreadable(command: &'static str, paths: &Paths, error: StoreError) -> Report {
    failed(
        command,
        "Nothing was read from the history, and nothing was deleted.",
        format!(
            "SURE read {} and could not make sense of one of the records in it: {}. Nothing was \
             skipped: a session shown with a record missing from it would look complete.",
            escape_control_characters(&paths.store_file().display().to_string()),
            error
        ),
    )
}

/// A read that started and could not finish.
fn read_failed(
    command: &'static str,
    error: sure_core::session_event_store::SessionEventStoreError,
) -> Report {
    failed(
        command,
        "Nothing was read from the history, and nothing was deleted.",
        error.to_string(),
    )
}

/// A run that tried and could not finish.
fn failed(command: &'static str, what: &'static str, detail: String) -> Report {
    Report::Failed(Box::new(Failed {
        command,
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
pub fn human(report: &HistoryReport, out: &mut impl Write) -> io::Result<()> {
    match &report.outcome {
        HistoryOutcome::NothingRecorded => {
            writeln!(out, "SURE has recorded nothing on this machine yet.")?;
            writeln!(out)?;
            row(out, "store", &clean(&report.store))?;
            writeln!(out)?;
            writeln!(
                out,
                "Nothing was created: that file appears the first time SURE records an event, \
                 and a command that reported an empty history by making one would have changed \
                 the thing it was reporting."
            )
        }
        HistoryOutcome::NoSessions => {
            writeln!(
                out,
                "SURE has recorded no harness sessions on this machine."
            )?;
            writeln!(
                out,
                "`sure check` records nothing; `sure repair` and `sure recheck` record their \
                 results in the store. A session is recorded only when SURE is started by a \
                 harness integration."
            )?;
            writeln!(out)?;
            row(out, "store", &clean(&report.store))?;
            writeln!(out)?;
            retention_note(out)
        }
        HistoryOutcome::Listed {
            sessions,
            total,
            limit,
        } => {
            writeln!(
                out,
                "SURE has recorded {} on this machine.",
                plural(*total, "session", "sessions")
            )?;
            writeln!(out)?;
            row(out, "store", &clean(&report.store))?;
            if total > limit {
                row(
                    out,
                    "showing",
                    &format!("the newest {limit} of {total} (--limit N shows more)"),
                )?;
            }
            writeln!(out)?;
            for session in sessions {
                write_session(session, out)?;
            }
            retention_note(out)
        }
        HistoryOutcome::Shown { session, events } => {
            writeln!(out, "One session, as SURE recorded it.")?;
            writeln!(out)?;
            row(out, "store", &clean(&report.store))?;
            writeln!(out)?;
            write_session(session, out)?;

            writeln!(
                out,
                "{} recorded in this session.",
                match events.len() {
                    0 => "No events were".to_owned(),
                    count => plural(u64::try_from(count).unwrap_or(0), "event", "events"),
                }
            )?;
            writeln!(out)?;
            for shown in events {
                write_event(shown, out)?;
            }
            retention_note(out)
        }
        HistoryOutcome::Deleted { scope, deleted } => {
            if deleted.is_empty() {
                writeln!(out, "Nothing was deleted.")?;
                writeln!(out)?;
                writeln!(
                    out,
                    "The scope matched no row in this store, so no session, event, record, \
                     decision or full recording was removed."
                )?;
            } else {
                writeln!(out, "SURE deleted what the scope named.")?;
            }
            writeln!(out)?;
            row(out, "scope", scope)?;
            row(out, "sessions", &deleted.sessions.to_string())?;
            row(out, "events", &deleted.events.to_string())?;
            row(out, "records", &deleted.records.to_string())?;
            row(out, "decisions", &deleted.decisions.to_string())?;
            row(out, "full recordings", &deleted.recordings.to_string())?;
            row(out, "store", &clean(&report.store))?;
            writeln!(out)?;
            if report.store_present {
                writeln!(
                    out,
                    "Everything the scope named went in one transaction, or nothing did: a \
                     delete that stopped partway removes nothing at all."
                )
            } else {
                writeln!(
                    out,
                    "There was nothing to delete: SURE has never recorded anything on this \
                     machine, and it did not create a store in order to delete from one."
                )
            }
        }
    }
}

/// The rows one session has.
fn write_session(session: &StoredSession, out: &mut impl Write) -> io::Result<()> {
    row(out, "session", &clean(session.sure_session_id.as_str()))?;
    if let Some(harness_id) = &session.harness_session_id {
        row(out, "harness session", &clean(harness_id))?;
    }
    row(out, "project", &clean(&session.project_root))?;
    row(out, "harness", &clean(&session.harness_source))?;
    row(out, "started", &clean(&session.started_at))?;
    row(out, "kept for", &days(session.retention_days))?;
    row(out, "kept until", &until(session.retained_until_ms))?;
    writeln!(out)
}

/// One event, and the record it wrote.
fn write_event(shown: &ShownEvent, out: &mut impl Write) -> io::Result<()> {
    let event = &shown.event;
    row(out, "event", &clean(&event.event_type))?;
    row(out, "at", &clean(&event.timestamp))?;
    row(out, "event id", &clean(event.event_id.as_str()))?;
    match event.capability_tier {
        Some(tier) => row(
            out,
            "capability",
            &format!("tier {} ({})", tier.number(), tier.as_str()),
        )?,
        None => row(out, "capability", "not reported")?,
    }
    row(out, "kept for", &days(event.retention_days))?;
    row(out, "kept until", &until(event.retained_until_ms))?;
    match &shown.record {
        Some(record) => {
            row(
                out,
                "record",
                &format!(
                    "{} {}, written {}",
                    record.kind,
                    record.id,
                    Timestamp::from_millis(record.written_at_ms)
                ),
            )?;
            // A full recording's deadline is inside its own document rather than
            // in a column, because `records` has none: the document is what a
            // recording was written as. Printing it is how the retention a user
            // configured becomes visible in the surface they inspect.
            if let Some(retained_until) = record
                .document
                .get("retained_until_ms")
                .and_then(Value::as_i64)
            {
                row(
                    out,
                    "recording until",
                    &Timestamp::from_millis(retained_until).to_string(),
                )?;
            }
        }
        None => row(out, "record", "none")?,
    }
    write_decision(shown.decision.as_ref(), out)?;
    writeln!(out)
}

/// What SURE decided about one event.
///
/// Printed under the event it was about, and in the words the user was shown:
/// the verdict comes from `ProtectionDecisionKind::as_str`, the danger from
/// `Danger::as_str`, and the reason is the sentence the harness was answered
/// with. Nothing here re-reads a request or re-decides anything — this is the
/// row that was written when the decision was taken, or it is absent.
///
/// An event with no decision prints nothing extra rather than a line saying
/// "none": most events are not tool requests, and SURE reaching no decision about
/// them is not a fact about the user's project. The two cases are told apart by
/// the event type printed above, which is where a reader looks for them anyway.
fn write_decision(decision: Option<&DecisionRecord>, out: &mut impl Write) -> io::Result<()> {
    let Some(decision) = decision else {
        return Ok(());
    };
    row(out, "decision", decision.decision.as_str())?;
    if let Some(danger) = decision.danger {
        row(out, "danger", danger.as_str())?;
    }
    row(out, "tool", &clean(&decision.tool))?;
    if let Some(grant) = decision.allowance {
        // The row id rather than the grant's words: the grant is a row of its
        // own, and the reason line below already says what this request was
        // allowed to do. What a reader cannot get any other way is *which*
        // allowance paid for it.
        row(
            out,
            "allowance",
            &format!("grant {grant} was spent by this request"),
        )?;
    }
    match &decision.reason {
        Some(reason) => row(out, "reason", &clean(reason))?,
        None => row(out, "reason", "none")?,
    }
    Ok(())
}

/// The sentence that keeps a deadline from being read as a deletion.
///
/// Printed by every read, and it is a fact about this build rather than a
/// promise: no pruning job exists, so a date in the past means the row is still
/// here.
fn retention_note(out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "`kept until` is a date SURE recorded, not a job it runs: nothing has been removed \
         because a date passed. `sure history delete` is what removes a session."
    )?;
    writeln!(out)?;
    Ok(())
}

/// A number of days, in words.
fn days(count: i64) -> String {
    format!("{} {}", count, if count == 1 { "day" } else { "days" })
}

/// A retention deadline, in RFC 3339, UTC.
fn until(retained_until_ms: i64) -> String {
    format!(
        "{} ({} ms since the epoch)",
        Timestamp::from_millis(retained_until_ms),
        retained_until_ms
    )
}

/// A count and its noun.
fn plural(count: u64, one: &str, many: &str) -> String {
    format!("{} {}", count, if count == 1 { one } else { many })
}

/// Text out of the store, safe to put on a line.
///
/// A project root, a harness name and a timestamp are all written by a harness,
/// and a value with a newline in it can add a line that reads as SURE's own. The
/// same treatment `sure_core::diagnostics` gives every field it prints.
fn clean(text: &str) -> String {
    escape_control_characters(text)
}

/// One labelled row, in `crate::doctor`'s layout.
fn row(out: &mut impl Write, label: &str, value: &str) -> io::Result<()> {
    writeln!(out, "  {label:<LABEL$} {value}")
}

// --- the machine form ---------------------------------------------------

/// The frame's `details`, as [`crate::report::Report::frame`] writes it.
///
/// Built from the same values [`human`] renders, so that a script and a person
/// are reading one result. Ids are strings, instants are both the RFC 3339 text
/// the row holds and the milliseconds it was computed from, and nothing here is
/// a summary of anything else in the frame.
#[must_use]
pub fn machine(report: &HistoryReport) -> Value {
    let mut details = json!({
        "store": report.store,
        "store_present": report.store_present,
        "removed": match &report.outcome {
            HistoryOutcome::Deleted { deleted, .. } => !deleted.is_empty(),
            _ => false,
        },
    });
    match &report.outcome {
        HistoryOutcome::NothingRecorded | HistoryOutcome::NoSessions => {
            details["sessions"] = json!([]);
            details["total"] = json!(0);
        }
        HistoryOutcome::Listed {
            sessions,
            total,
            limit,
        } => {
            details["total"] = json!(total);
            details["limit"] = json!(limit);
            details["sessions"] = json!(sessions.iter().map(session_json).collect::<Vec<_>>());
        }
        HistoryOutcome::Shown { session, events } => {
            details["session"] = session_json(session);
            details["events"] = json!(
                events
                    .iter()
                    .map(|shown| {
                        let mut value = event_json(&shown.event);
                        value["record"] = match &shown.record {
                            None => Value::Null,
                            Some(record) => json!({
                                "id": record.id,
                                "kind": record.kind.as_str(),
                                "written_at_ms": record.written_at_ms,
                                "written_at": Timestamp::from_millis(record.written_at_ms)
                                    .to_string(),
                                "retained_until_ms": record
                                    .document
                                    .get("retained_until_ms")
                                    .and_then(Value::as_i64),
                            }),
                        };
                        value["decision"] = match &shown.decision {
                            None => Value::Null,
                            Some(decision) => decision_json(decision),
                        };
                        value
                    })
                    .collect::<Vec<_>>()
            );
        }
        HistoryOutcome::Deleted { scope, deleted } => {
            details["scope"] = json!(scope);
            details["deleted"] = json!({
                "sessions": deleted.sessions,
                "events": deleted.events,
                "records": deleted.records,
                "decisions": deleted.decisions,
                "recordings": deleted.recordings,
            });
        }
    }
    details
}

/// One decision row, as a script reads it.
///
/// The names are the ones the row stores — `"block"`, `"broad_delete"` — rather
/// than the sentences [`write_decision`] prints, because a script compares and a
/// person reads. The reason is passed through as it was written: it is prose, and
/// a machine form that rewrote it would be a second place for the sentence to be
/// wrong.
fn decision_json(decision: &DecisionRecord) -> Value {
    json!({
        "event_id": decision.event_id.as_str(),
        "decision": decision.decision.as_str(),
        "danger": decision.danger.map(Danger::wire_name),
        "tool": &decision.tool,
        "reason": &decision.reason,
        "allowance": decision.allowance,
    })
}

/// One session row, as a script reads it.
fn session_json(session: &StoredSession) -> Value {
    json!({
        "row_id": session.row_id,
        "sure_session_id": session.sure_session_id.as_str(),
        "harness_session_id": session.harness_session_id,
        "project_root": session.project_root,
        "project_fingerprint": session.project_fingerprint,
        "harness": session.harness_source,
        "capability_tier": session.capability_tier.map(|tier| tier.as_str()),
        "started_at": session.started_at,
        "retention_days": session.retention_days,
        "retained_until_ms": session.retained_until_ms,
    })
}

/// One event row, as a script reads it.
fn event_json(event: &StoredEvent) -> Value {
    json!({
        "row_id": event.row_id,
        "event_id": event.event_id.as_str(),
        "session_row_id": event.session_row_id,
        "event_type": event.event_type,
        "timestamp": event.timestamp,
        "timestamp_ms": event.timestamp_ms,
        "capability_tier": event.capability_tier.map(|tier| tier.as_str()),
        "retention_days": event.retention_days,
        "retained_until_ms": event.retained_until_ms,
        "record_row_id": event.record_row_id,
    })
}
