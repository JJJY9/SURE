//! SURE's local record store.
//!
//! One SQLite file, at the user-level data directory, holding one row per
//! document SURE wrote down. `docs/architecture/STORAGE_AND_DATA_PATHS.md` is
//! the rule this implements; this module is where it becomes code.
//!
//! # Why SQLite, and why bundled
//!
//! `docs/architecture/RUST_DESIGN.md` names "bundled/portable SQLite binding" as
//! the intended choice, and the acceptance criterion is that storage *packages
//! without requiring system SQLite*. `rusqlite`'s `bundled` feature compiles
//! SQLite from source into `sure.exe`, so an installation carries its own
//! database engine. The alternative — linking whatever `sqlite3.dll` happens to
//! be on the machine — would make SURE's behaviour depend on a library the user
//! did not install for SURE and cannot tell us about, and a lock or page-size
//! difference there is not something SURE could detect or report honestly.
//!
//! A hand-written storage engine was the other option, and it was rejected for
//! the same reason the schemas are checked by a hand-written validator only
//! after that was argued for: crash-safe transactional writes and multi-process
//! locking are the two things SURE most needs from this layer, and they are
//! exactly the two things an ad-hoc file format gets wrong in ways that show up
//! months later as records that lost their tail. SQLite is the piece of this
//! system that has been wrong for forty years in public and is now right.
//!
//! # The concurrency contract
//!
//! `docs/architecture/ARCHITECTURE.md` and `RUST_DESIGN.md` both name the case:
//! short-lived hook processes contend for the same database. `sure hook ingest`
//! may be started by several harness events at once, each process opening the
//! store, writing one row and exiting.
//!
//! The defined behaviour, in full:
//!
//! 1. **Every write is one transaction**, `BEGIN IMMEDIATE` to `COMMIT`. A
//!    process that dies part-way through leaves either the whole row or no row,
//!    never half of one. This is the property that makes a truncated record
//!    impossible rather than merely unlikely.
//! 2. **Writers serialise.** At most one holds the write lock; the others wait
//!    in SQLite's busy handler, not in a retry loop of SURE's invention.
//! 3. **The wait is bounded**, by [`StoreOptions::busy_timeout`]. Past it,
//!    SQLite returns `SQLITE_BUSY` and SURE reports [`StoreError::Busy`].
//! 4. **A timeout is reported, never retried and never dropped.** There is no
//!    outer retry loop, because an unbounded retry turns "the database is
//!    contended" into "SURE hangs", and a dropped event turns it into a project
//!    with nothing recorded about it. Both are worse than a message.
//! 5. **`synchronous = FULL`.** A committed write survives power loss. Evidence
//!    that can vanish without a trace is worse than evidence that is slower;
//!    each hook process writes one row, so the cost is one fsync per event.
//!
//! Read concurrency depends on the journal mode: [`Store::journal_mode`] reports
//! what this file actually got. Under `wal`, readers never block the writer and
//! the writer never blocks readers. On a filesystem that refuses `wal` — a
//! network share, sometimes — SQLite falls back to `delete`, and readers then
//! wait for the writer. Writes are unaffected either way, which is why the
//! contract above is stated unconditionally and this paragraph is not.
//!
//! # The one wait that is not the busy handler's
//!
//! Point 2 above has an exception, and it is the exception a new installation
//! meets first. Putting a rollback-journal file into `wal` needs a moment of
//! exclusive access, and SQLite's busy handler deliberately does not cover it —
//! `sqlite3_busy_handler`'s own documentation names the journal-mode change as a
//! case where waiting could deadlock, so the change returns `SQLITE_BUSY` at
//! once. Opening a database that does not exist yet is exactly that moment, and
//! several hooks firing together is exactly that contention.
//!
//! [`establish_journal_mode`] therefore waits for it, up to the same
//! [`StoreOptions::busy_timeout`], and reports [`StoreError::Busy`] if it runs
//! out. It is the only retry in this module, and it is bounded by the same
//! deadline as everything else rather than by a count of attempts.
//!
//! # Where the file goes
//!
//! [`Store::open`] takes the [`crate::paths::Paths`] and the project root, and
//! refuses a project that contains the store. That check is not optional and is
//! not the caller's to remember: evidence inside the project can be edited by
//! the agent whose work is being judged, so a stored result would stop being
//! evidence of anything. [`Store::open_at`] skips the check and exists for
//! tests and for `sure doctor`, which has no project in hand.
//!
//! # What is not here
//!
//! No asynchronous API and no connection pool. `RUST_DESIGN.md` says "do not
//! hold synchronous DB resources across `.await`", and the way that is honoured
//! is that this workspace has no async runtime at all — a rule enforced by a
//! test in `tests/store_packaging.rs` rather than by discipline. If one arrives,
//! that test fails and the store has to be reconsidered, which is the point.

mod error;
mod migrations;
mod record;

pub use error::StoreError;
pub use migrations::{LATEST as LATEST_SCHEMA_VERSION, Migration, MigrationError};
pub use record::{ACKNOWLEDGEMENT, ALLOWANCE, APPROVAL, RECORDING, RecordKind, StoredRecord};
pub use sure_protocol::documents::DocumentKind;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use rusqlite::types::Value as SqlValue;
use serde_json::Value;
use sure_domain::execution::HostConsent;
use sure_domain::ids::FingerprintId;

use crate::allowance::{self, AllowanceRecord};
use crate::diagnostics::Timestamp;
use crate::paths::Paths;
use crate::redact;

/// How long SURE waits for another process before giving up on a write.
///
/// Five seconds, chosen rather than inherited. Long enough that a hook process
/// queueing behind a handful of others succeeds without anyone noticing; short
/// enough that a wedged process produces a message while the user is still
/// looking at the terminal. `RUST_DESIGN.md` asks for the busy semantics to be
/// deliberate; this number is the deliberation.
pub const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The SQLite `synchronous` level SURE runs at. `2` is `FULL`.
///
/// The numeric form rather than the name because `PRAGMA synchronous` is parsed
/// as a number first, and a name that arrived as a quoted string would be a
/// silent fallback to the default rather than an error.
const SYNCHRONOUS_FULL: i64 = 2;

/// How the store is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreOptions {
    /// How long a write waits for the write lock before reporting
    /// [`StoreError::Busy`].
    pub busy_timeout: Duration,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            busy_timeout: DEFAULT_BUSY_TIMEOUT,
        }
    }
}

/// Which records to look at.
///
/// Every field is optional, and the default filter — [`HistoryFilter::default`]
/// — is "everything, except recordings". That default is the privacy rule from
/// `docs/security/PRIVACY.md` expressed as a type: full recordings are only
/// reached by a caller that asked for them by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HistoryFilter<'a> {
    /// Only records about this project state.
    pub project_fingerprint: Option<&'a FingerprintId>,
    /// Only records of this kind.
    pub kind: Option<RecordKind>,
    /// Whether full recordings are included.
    pub include_recordings: bool,
}

impl HistoryFilter<'_> {
    /// Everything about one project, recordings excluded.
    #[must_use]
    pub fn for_project(fingerprint: &FingerprintId) -> HistoryFilter<'_> {
        HistoryFilter {
            project_fingerprint: Some(fingerprint),
            ..HistoryFilter::default()
        }
    }

    /// Only full recordings, for the delete path.
    #[must_use]
    pub fn recordings() -> Self {
        Self {
            kind: Some(RecordKind::Recording),
            include_recordings: true,
            project_fingerprint: None,
        }
    }

    /// Only recorded approvals, for one project state.
    ///
    /// A named constructor rather than a struct literal at the call site, for
    /// the same reason [`HistoryFilter::recordings`] is one: the filter that
    /// answers *what has SURE been allowed to run here* should be readable as
    /// that sentence, and an approval is always about a project state
    /// (`docs/architecture/EVIDENCE_MODEL.md`), so there is no version of this
    /// filter that does not name one.
    #[must_use]
    pub fn approvals(fingerprint: &FingerprintId) -> HistoryFilter<'_> {
        HistoryFilter {
            project_fingerprint: Some(fingerprint),
            kind: Some(RecordKind::Approval),
            include_recordings: false,
        }
    }
}

/// The local record store, open.
///
/// Not `Clone`: a second handle is a second connection, and a caller that wants
/// one should say so by calling [`Store::open_at`] again rather than by copying
/// a value that looks free.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
    path: PathBuf,
    journal_mode: String,
    /// Kept so that a write which timed out can say how long SURE waited, and
    /// so that contention during migration reports as contention rather than as
    /// a failed migration.
    busy_timeout: Duration,
}

impl Store {
    /// Open the store for a project SURE is checking.
    ///
    /// # Errors
    ///
    /// [`StoreError::Location`] if the store would be inside `project_root`,
    /// then whatever [`Store::open_at`] can return.
    pub fn open(paths: &Paths, project_root: &Path) -> Result<Self, StoreError> {
        paths.ensure_outside(project_root)?;
        Self::open_at(&paths.store_file())
    }

    /// Open the store at a path, with no project boundary check.
    ///
    /// For tests, and for callers that are not checking a project —
    /// `sure doctor`, and `sure history`, which reads records about projects
    /// rather than about the one it is run from. Everything else wants
    /// [`Store::open`], which cannot be used to put evidence inside the tree
    /// being judged.
    ///
    /// # Errors
    ///
    /// [`StoreError::CreateDirectory`] if the parent directory cannot be made,
    /// [`StoreError::Open`] if the file cannot be opened, and
    /// [`StoreError::Migration`] if the schema cannot be brought up to date.
    pub fn open_at(path: &Path) -> Result<Self, StoreError> {
        Self::open_with(path, StoreOptions::default())
    }

    /// Open the store with explicit options.
    ///
    /// The parent directory is created if it is missing. SURE creates its own
    /// application-data directory; it does not create the project it was
    /// pointed at, and nothing here creates a directory that is not the store's.
    ///
    /// # Errors
    ///
    /// As [`Store::open_at`].
    pub fn open_with(path: &Path, options: StoreOptions) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|error| StoreError::CreateDirectory {
                path: parent.to_path_buf(),
                message: error.to_string(),
            })?;
        }

        let connection = Connection::open(path).map_err(|error| StoreError::Open {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        connection
            .busy_timeout(options.busy_timeout)
            .map_err(|error| StoreError::Open {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;

        // Journal mode first, and outside any transaction: `journal_mode` is
        // the one pragma that cannot be changed inside one, and migrations take
        // transactions.
        let journal_mode = establish_journal_mode(&connection, path, options.busy_timeout)?;

        // `synchronous` is per-connection rather than per-file, so unlike the
        // journal mode it has to be set on every open.
        connection
            .pragma_update(None, "synchronous", SYNCHRONOUS_FULL)
            .map_err(|error| StoreError::Open {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;

        let store = Self {
            connection,
            path: path.to_path_buf(),
            journal_mode,
            busy_timeout: options.busy_timeout,
        };
        // Migration happens here rather than in an explicit step before the
        // store is usable, because a short-lived process — a hook, one command —
        // must not be able to write to a file it has not brought up to date.
        if let Err(error) = migrations::apply(&store.connection) {
            return Err(store.migration_error(error));
        }
        Ok(store)
    }

    /// Turn a migration failure into the store's own vocabulary.
    ///
    /// The one case worth separating: contention while migrating is the same
    /// condition as contention while writing, and it should read the same way,
    /// with the wait this store was configured with. Left as
    /// [`StoreError::Migration`] it would read as a broken history file and send
    /// the user looking for a fault that is not there.
    fn migration_error(&self, error: migrations::MigrationError) -> StoreError {
        match error {
            migrations::MigrationError::Busy { .. } => StoreError::Busy {
                path: self.path.clone(),
                waited_ms: self.busy_timeout.as_millis() as u64,
            },
            other => StoreError::Migration(other),
        }
    }

    /// Where the file is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The journal mode the file actually has.
    ///
    /// Not necessarily `wal` — see the module documentation. Reported rather
    /// than assumed, so `sure doctor` can say what this installation got.
    #[must_use]
    pub fn journal_mode(&self) -> &str {
        &self.journal_mode
    }

    /// The schema version of the open file.
    ///
    /// # Errors
    ///
    /// [`StoreError::Migration`] if the header cannot be read.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        Ok(migrations::version(&self.connection)?)
    }

    /// The underlying SQLite connection, for callers that need to run their own
    /// SQL inside the store's transaction and concurrency contract.
    ///
    /// Not public: a caller that needs this is part of `sure-core` and should
    /// use `pub(crate)` access. External crates use the typed methods.
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Redact, validate against the schema, and stringify a document.
    ///
    /// Returns the JSON text that would be stored, without writing it. Used by
    /// callers that manage their own transaction and need to insert into
    /// `records` atomically with other tables.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotStorable`], [`StoreError::Rejected`],
    /// [`StoreError::Schema`], or [`StoreError::MalformedRow`].
    pub(crate) fn validate_and_stringify(
        &self,
        kind: RecordKind,
        document: &Value,
    ) -> Result<String, StoreError> {
        if !kind.is_storable() {
            return Err(StoreError::NotStorable { kind });
        }
        let document = redact_document(document);

        match kind.document() {
            Some(document_kind) => {
                let schema = document_kind.schema().map_err(|error| StoreError::Schema {
                    kind,
                    message: error.to_string(),
                })?;
                let violations = schema.validate(&document);
                if !violations.is_empty() {
                    return Err(StoreError::Rejected { kind, violations });
                }
            }
            None if !document.is_object() => {
                return Err(StoreError::Rejected {
                    kind,
                    violations: vec![sure_protocol::schema::Violation {
                        schema: "(no schema: a recording has no fixed shape)".to_owned(),
                        path: String::new(),
                        kind: sure_protocol::schema::ViolationKind::WrongType {
                            expected: "an object".to_owned(),
                            found: sure_protocol::schema::type_name(&document).to_owned(),
                        },
                    }],
                });
            }
            None => {}
        }

        serde_json::to_string(&document).map_err(|error| StoreError::MalformedRow {
            id: 0,
            message: error.to_string(),
        })
    }

    /// Store a document, unbound to any project.
    ///
    /// # Errors
    ///
    /// [`StoreError::Rejected`] if the document does not match the schema for
    /// its kind, [`StoreError::Busy`] if another process held the write lock for
    /// longer than [`StoreOptions::busy_timeout`].
    pub fn append(&self, kind: RecordKind, document: &Value) -> Result<i64, StoreError> {
        self.insert(kind, document, None, None)
    }

    /// Store a document about a named project state.
    ///
    /// The root is stored as text, and the fingerprint beside it, so a reader
    /// can tell later whether the record is about the project as it is now or as
    /// it was. `docs/architecture/EVIDENCE_MODEL.md`: a result that does not
    /// name its project state can be read against a later one, which is how a
    /// stale pass becomes a false green.
    ///
    /// # Errors
    ///
    /// As [`Store::append`].
    pub fn append_for(
        &self,
        kind: RecordKind,
        document: &Value,
        project_root: &str,
        fingerprint: &FingerprintId,
    ) -> Result<i64, StoreError> {
        self.insert(
            kind,
            document,
            Some(project_root),
            Some(fingerprint.as_str()),
        )
    }

    /// Store raw captured material.
    ///
    /// A separate method rather than `append(RecordKind::Recording, ..)` so that
    /// writing a recording is a thing a call site has to have typed on purpose.
    /// `docs/security/PRIVACY.md` allows full recording only under explicit
    /// opt-in; the caller owns that decision, and this method's name is where it
    /// is made.
    ///
    /// Unlike a document, a recording is not checked against a schema — there
    /// is none, because it is not a statement about a project. It must still be
    /// a JSON object, so that a recording cannot be a bare string that a later
    /// reader has to guess the shape of.
    ///
    /// # Errors
    ///
    /// As [`Store::append`], plus [`StoreError::Rejected`] if the value is not
    /// an object.
    pub fn append_recording(
        &self,
        recording: &Value,
        project_root: Option<&str>,
    ) -> Result<i64, StoreError> {
        self.insert(RecordKind::Recording, recording, project_root, None)
    }

    /// Store a consent the user gave, so that it can be read back afterwards.
    ///
    /// A method of its own rather than
    /// `append_for(RecordKind::Approval, ..)`, for the reason
    /// [`Store::append_recording`] is one: `ADR 0009` is that host execution is
    /// conditional on *recorded* per-command consent, so writing one down is a
    /// thing a call site should have to have typed on purpose.
    ///
    /// The document is the [`HostConsent`] itself rather than a projection of
    /// it. A projection would be a second reading of the same approval, and the
    /// audit question is *was this exact command approved*, which only the
    /// record as it was given can answer.
    ///
    /// It takes a project state for the same reason every other record about a
    /// project does: a consent given for one project state and read against
    /// another is a consent for something else.
    ///
    /// # Errors
    ///
    /// [`StoreError::MalformedRow`] if the consent cannot be turned into JSON,
    /// plus everything [`Store::append`] reports. There is no schema for this
    /// kind, so there is no [`StoreError::Rejected`] from a schema.
    pub fn append_approval(
        &self,
        consent: &HostConsent,
        project_root: &str,
        fingerprint: &FingerprintId,
    ) -> Result<i64, StoreError> {
        let document = serde_json::to_value(consent).map_err(|error| StoreError::MalformedRow {
            id: 0,
            message: error.to_string(),
        })?;
        self.insert(
            RecordKind::Approval,
            &document,
            Some(project_root),
            Some(fingerprint.as_str()),
        )
    }

    /// Store a one-time allowance, so that the request it was recorded for can
    /// spend it.
    ///
    /// A method of its own rather than `append_for(RecordKind::Allowance, ..)`,
    /// for the reason [`Store::append_approval`] is one: a grant is a permission
    /// the user gave, and writing one down is a thing a call site should have to
    /// have typed on purpose. `crate::allowance` states what the document holds
    /// and what it deliberately does not.
    ///
    /// # Errors
    ///
    /// [`StoreError::MalformedRow`] if the record cannot be turned into JSON,
    /// plus everything [`Store::append`] reports. There is no schema for this
    /// kind, so there is no [`StoreError::Rejected`] from one.
    pub fn append_allowance(
        &self,
        allowance: &AllowanceRecord,
        project_root: &str,
        fingerprint: &FingerprintId,
    ) -> Result<i64, StoreError> {
        let document =
            serde_json::to_value(allowance).map_err(|error| StoreError::MalformedRow {
                id: 0,
                message: error.to_string(),
            })?;
        self.insert(
            RecordKind::Allowance,
            &document,
            Some(project_root),
            Some(fingerprint.as_str()),
        )
    }

    /// Spend one outstanding allowance for a request, if there is one.
    ///
    /// Returns the row id of the grant that was spent, or `None` when there was
    /// nothing to spend.
    ///
    /// **The read and the write are one transaction**, and that is the reason
    /// this lives in the store rather than beside the question the pure
    /// [`allowance::outstanding`] answers: a harness calls a hook as a fresh
    /// process per event, two identical requests can arrive at once, and a check
    /// in one transaction followed by a write in another would let one
    /// allowance be spent twice by two processes that both looked when it was
    /// outstanding.
    ///
    /// `None` also covers a store holding more allowance rows than
    /// [`allowance::SCAN_LIMIT`]: SURE does not read past the bound, and the
    /// direction it fails in is the one that spends nothing.
    ///
    /// The use is written with no project fingerprint. A grant is a statement
    /// about the project state the user made it in and carries that state; a
    /// use is a statement about SURE's own permission and carries the row it
    /// spent instead.
    ///
    /// # Errors
    ///
    /// [`StoreError::Decode`] if a row of this kind cannot be read, plus the
    /// store's own write errors. A use that could not be written is reported
    /// rather than swallowed: an allowance that was allowed without being spent
    /// is a permission that never ends.
    pub fn spend_allowance(
        &self,
        project_root: &str,
        tool: &str,
        subject: &str,
        now_ms: i64,
    ) -> Result<Option<i64>, StoreError> {
        let filter = HistoryFilter {
            project_fingerprint: None,
            kind: Some(RecordKind::Allowance),
            include_recordings: false,
        };
        self.transaction(|connection| {
            let rows = self.history(&filter, allowance::SCAN_LIMIT)?;
            if rows.len() >= allowance::SCAN_LIMIT {
                return Ok(None);
            }
            let Some(grant) = allowance::outstanding(&rows, project_root, tool, subject, now_ms)?
            else {
                return Ok(None);
            };

            let use_of = AllowanceRecord::Spent(allowance::Spent {
                grant,
                spent_at_ms: now_ms,
            });
            let document =
                serde_json::to_value(use_of).map_err(|error| StoreError::MalformedRow {
                    id: 0,
                    message: error.to_string(),
                })?;
            let text = self.validate_and_stringify(RecordKind::Allowance, &document)?;
            self.write_row(
                connection,
                RecordKind::Allowance,
                &text,
                Timestamp::now().as_millis(),
                Some(project_root),
                None,
            )?;
            Ok(Some(grant))
        })
    }

    /// Read records, newest first.
    ///
    /// `limit` is the maximum number of records to return, and `0` returns none.
    /// It is not treated as "no limit": a caller that computed a limit of zero
    /// made a mistake, and an empty result says so, where an unbounded query
    /// would hide it behind a slow command.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnknownKind`] if a row names a kind this build does not
    /// know, [`StoreError::MalformedRow`] if a row's document is not JSON, and
    /// [`StoreError::Open`]-family errors from the query itself. A single bad
    /// row stops the read rather than being skipped: silently returning the
    /// other records would make a history with a hole in it look complete.
    pub fn history(
        &self,
        filter: &HistoryFilter<'_>,
        limit: usize,
    ) -> Result<Vec<StoredRecord>, StoreError> {
        self.history_with_floor(filter, None, limit)
    }

    /// Read records written at or after `since_ms`, newest first.
    ///
    /// The same query as [`Store::history`] with one more condition, so that a
    /// reader that only cares about what happened after a known moment does not
    /// spend its `limit` on older rows. A reader that called [`Store::history`]
    /// and filtered the result in Rust would be spending the bound on rows it
    /// was about to discard — and, because the query is newest-first, would get
    /// a *truncated* answer that looks exactly like a complete one (see
    /// `recheck_lifecycle::HISTORY_SCAN_LIMIT` for why that direction matters).
    ///
    /// `since_ms` is inclusive: a record written at the same millisecond as the
    /// moment asked about counts as "at or after" it. Nothing in this store
    /// orders two writes within one millisecond; the inclusive end is the one
    /// that cannot drop a write made in the same millisecond as the row it is
    /// compared against.
    ///
    /// # Errors
    ///
    /// As [`Store::history`].
    pub(crate) fn history_since(
        &self,
        filter: &HistoryFilter<'_>,
        since_ms: i64,
        limit: usize,
    ) -> Result<Vec<StoredRecord>, StoreError> {
        self.history_with_floor(filter, Some(since_ms), limit)
    }

    fn history_with_floor(
        &self,
        filter: &HistoryFilter<'_>,
        since_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<StoredRecord>, StoreError> {
        let (where_clause, parameters) = filter.sql();
        let (where_clause, mut values) = match since_ms {
            None => (where_clause, parameters),
            Some(since_ms) => {
                let mut values = parameters;
                values.push(SqlValue::Integer(since_ms));
                let clause = if where_clause.is_empty() {
                    String::from(" WHERE written_at_ms >= ?")
                } else {
                    format!("{where_clause} AND written_at_ms >= ?")
                };
                (clause, values)
            }
        };
        let sql = format!(
            "SELECT id, kind, document_version, written_at_ms, project_root, \
             project_fingerprint, document FROM records{where_clause} \
             ORDER BY written_at_ms DESC, id DESC LIMIT ?"
        );
        values.push(SqlValue::Integer(limit as i64));

        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| self.open_error(error))?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(values), |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(|error| self.open_error(error))?;

        let mut records = Vec::new();
        for row in rows {
            records.push(self.stored_record(row.map_err(|error| self.open_error(error))?)?);
        }
        Ok(records)
    }

    /// One record, by its row id.
    ///
    /// `None` when no row has that id — one that was deleted, or an id from
    /// another store. Not an error: "there is no record 42 here" is an answer
    /// about the store, and a caller that needs the row to exist is the one
    /// that should decide what a missing one means.
    ///
    /// A separate read from [`Store::history`] because the id is the one thing
    /// its filter cannot express, and the id is what a caller has: a
    /// `session_events.record_row_id` names the record an event wrote, and
    /// resolving that number to the row it names is how a user finds out what
    /// SURE kept about them.
    ///
    /// It reads every kind, recordings included. That is not a relaxation of
    /// [`HistoryFilter`]'s privacy rule — the rule is that a *listing* does not
    /// hand over raw content unless it was asked for, and this is not a listing.
    /// The caller already has the id, and it can only have got one from a row
    /// that named it.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnknownKind`] if the row names a kind this build does not
    /// know, [`StoreError::MalformedRow`] if its document is not JSON, and
    /// [`StoreError::Open`]-family errors from the query itself.
    pub fn record(&self, id: i64) -> Result<Option<StoredRecord>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, kind, document_version, written_at_ms, project_root, \
                 project_fingerprint, document FROM records WHERE id = ?1",
            )
            .map_err(|error| self.open_error(error))?;
        let mut rows = statement
            .query_map([id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(|error| self.open_error(error))?;

        match rows.next() {
            None => Ok(None),
            Some(row) => {
                let raw = row.map_err(|error| self.open_error(error))?;
                self.stored_record(raw).map(Some)
            }
        }
    }

    /// One row of `records`, as the tuple both readers select.
    ///
    /// Shared so that [`Store::history`] and [`Store::record`] cannot disagree
    /// about what a row means — including the two refusals below, which are the
    /// difference between a history with a hole in it and a read that stopped.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnknownKind`] if the kind is one this build does not know,
    /// [`StoreError::MalformedRow`] if the document is not JSON.
    fn stored_record(
        &self,
        (id, kind, version, written_at_ms, root, fingerprint, document): (
            i64,
            String,
            i64,
            i64,
            Option<String>,
            Option<String>,
            String,
        ),
    ) -> Result<StoredRecord, StoreError> {
        let kind =
            RecordKind::from_name(&kind).ok_or(StoreError::UnknownKind { id, name: kind })?;
        let document: Value =
            serde_json::from_str(&document).map_err(|error| StoreError::MalformedRow {
                id,
                message: error.to_string(),
            })?;
        Ok(StoredRecord {
            id,
            kind,
            document_version: u32::try_from(version).unwrap_or(0),
            written_at_ms,
            project_root: root,
            project_fingerprint: fingerprint,
            document,
        })
    }

    /// How many records match.
    ///
    /// # Errors
    ///
    /// [`StoreError::Open`]-family errors from the query.
    pub fn count(&self, filter: &HistoryFilter<'_>) -> Result<u64, StoreError> {
        let (where_clause, parameters) = filter.sql();
        let sql = format!("SELECT count(*) FROM records{where_clause}");
        let raw: i64 = self
            .connection
            .query_row(&sql, rusqlite::params_from_iter(parameters), |row| {
                row.get(0)
            })
            .map_err(|error| self.open_error(error))?;
        Ok(u64::try_from(raw).unwrap_or(0))
    }

    /// Delete every record matching, and report how many went.
    ///
    /// `docs/security/PRIVACY.md`: "Users must be able to inspect and delete
    /// local SURE history/recordings." This is the delete half; the inspect half
    /// is [`Store::history`].
    ///
    /// # Errors
    ///
    /// [`StoreError::Busy`] if another process held the write lock for longer
    /// than [`StoreOptions::busy_timeout`]. Nothing is deleted in that case.
    pub fn delete(&self, filter: &HistoryFilter<'_>) -> Result<u64, StoreError> {
        let (where_clause, parameters) = filter.sql();
        let sql = format!("DELETE FROM records{where_clause}");
        self.transaction(|connection| {
            let affected = connection
                .execute(&sql, rusqlite::params_from_iter(parameters))
                .map_err(|error| self.open_error(error))?;
            Ok(affected as u64)
        })
    }

    /// Delete every full recording, and report how many went.
    ///
    /// # Errors
    ///
    /// As [`Store::delete`].
    pub fn delete_recordings(&self) -> Result<u64, StoreError> {
        self.delete(&HistoryFilter::recordings())
    }

    /// Delete one record by row id, but only if it is the kind the caller
    /// expects.
    ///
    /// A targeted delete rather than a [`Store::delete`] filter because the one
    /// caller — `sure acknowledge --undo` — has a row id and nothing else it
    /// means: a filter would have to restate what identifies the row, and a
    /// filter that names the wrong thing deletes more than the user asked for.
    /// The kind is part of the statement so that an id from one table of the
    /// user's history can never remove a row of another.
    ///
    /// # Errors
    ///
    /// [`StoreError::Busy`] if another process held the write lock for longer
    /// than [`StoreOptions::busy_timeout`]. Nothing is deleted in that case.
    pub fn delete_record_of_kind(&self, id: i64, kind: RecordKind) -> Result<bool, StoreError> {
        self.transaction(|connection| {
            let affected = connection
                .execute(
                    "DELETE FROM records WHERE id = ?1 AND kind = ?2",
                    rusqlite::params![id, kind.as_str()],
                )
                .map_err(|error| self.open_error(error))?;
            Ok(affected > 0)
        })
    }

    /// Run SQLite's own consistency check.
    ///
    /// # Errors
    ///
    /// [`StoreError::Integrity`] if the file reports any problem at all. A
    /// damaged file is not read from: a record read out of one is a wrong answer
    /// about a project, and `sure doctor` is where the user finds out.
    pub fn integrity_check(&self) -> Result<(), StoreError> {
        let mut statement = self
            .connection
            .prepare("PRAGMA integrity_check")
            .map_err(|error| self.open_error(error))?;
        let problems = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| self.open_error(error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| self.open_error(error))?;

        // A healthy file answers with exactly one row, the word "ok". Anything
        // else — including no rows at all — is a problem, which is why this is
        // an equality rather than a "does it contain a problem" test.
        if problems.len() == 1 && problems[0] == "ok" {
            return Ok(());
        }
        Err(StoreError::Integrity { problems })
    }

    /// Redact, check against the schema, and write, in that order.
    ///
    /// The order is the whole point. Redacting first means the document that
    /// was validated is the document that was stored; validating first would
    /// allow a stored document that does not match its schema, which is the
    /// state [`StoreError::Rejected`] exists to make impossible.
    fn insert(
        &self,
        kind: RecordKind,
        document: &Value,
        project_root: Option<&str>,
        project_fingerprint: Option<&str>,
    ) -> Result<i64, StoreError> {
        let text = self.validate_and_stringify(kind, document)?;
        let written_at_ms = Timestamp::now().as_millis();

        self.transaction(|connection| {
            self.write_row(
                connection,
                kind,
                &text,
                written_at_ms,
                project_root,
                project_fingerprint,
            )
        })
    }

    /// The `INSERT` itself, with no transaction of its own.
    ///
    /// Split out of [`Store::insert`] so that a write which has to read and
    /// decide **inside the same transaction** — [`Store::spend_allowance`] —
    /// uses the one statement every other write uses, rather than a second copy
    /// of it that could drift from this one. The caller owns the transaction;
    /// [`Store::insert`] is the caller that opens one of its own.
    fn write_row(
        &self,
        connection: &Connection,
        kind: RecordKind,
        text: &str,
        written_at_ms: i64,
        project_root: Option<&str>,
        project_fingerprint: Option<&str>,
    ) -> Result<i64, StoreError> {
        connection
            .execute(
                "INSERT INTO records (kind, document_version, written_at_ms, \
                 project_root, project_fingerprint, document) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    kind.as_str(),
                    i64::from(sure_protocol::DOCUMENT_VERSION),
                    written_at_ms,
                    project_root,
                    project_fingerprint,
                    text
                ],
            )
            .map_err(|error| self.open_error(error))?;
        Ok(connection.last_insert_rowid())
    }

    /// Run one write as a single transaction.
    ///
    /// `BEGIN IMMEDIATE` rather than `BEGIN`: the write lock is taken now, so
    /// contention is met here — where the busy timeout applies and
    /// [`StoreError::Busy`] is produced — instead of at the first write, where
    /// a partial transaction would have to be unwound.
    fn transaction<T>(
        &self,
        body: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|error| self.write_error(error))?;

        match body(&self.connection) {
            Ok(value) => {
                self.connection
                    .execute_batch("COMMIT")
                    .map_err(|error| self.write_error(error))?;
                Ok(value)
            }
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// The error for a failure that could have been contention.
    fn write_error(&self, error: rusqlite::Error) -> StoreError {
        if is_busy(&error) {
            StoreError::Busy {
                path: self.path.clone(),
                // The wait this store was configured with, not the default. A
                // message that says "SURE waited 5000 ms" when it waited 50 is
                // a false statement about what just happened, and the reader
                // has no way to tell.
                waited_ms: self.busy_timeout.as_millis() as u64,
            }
        } else {
            self.open_error(error)
        }
    }

    fn open_error(&self, error: rusqlite::Error) -> StoreError {
        StoreError::Open {
            path: self.path.clone(),
            message: error.to_string(),
        }
    }
}

/// Whether SQLite refused because someone else holds the lock.
///
/// `DatabaseBusy` is the ordinary one: another connection is writing.
/// `DatabaseLocked` is the shared-cache variant, which SURE does not use but
/// which means the same thing to a caller, so it is reported the same way
/// rather than as an unexplained open failure.
pub(crate) fn is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

/// Replace credential-shaped values everywhere in a document.
///
/// Keys are left alone: they are the document's structure, and a key that had
/// been rewritten would fail the schema check and read as a malformed document
/// rather than as a redacted one. Values of every type are walked, and only
/// strings can change — redaction never turns a string into a number or a list
/// into an object, which is why validating after redacting is safe.
///
/// `docs/security/SECRET_REDACTION.md` is explicit that detection is imperfect
/// and this module does not claim otherwise. What this guarantees is narrower
/// and true: nothing reaches the file without having been through
/// [`crate::redact::redact`], and the test in this file —
/// `a_secret_in_a_document_does_not_reach_the_file`, beside the other store
/// tests rather than in a `tests/` file that does not exist — checks that
/// against the bytes on disk.
///
/// # There is no exception, and the explicit goal is the case that asked for one
///
/// `sure check --goal "…"` is the surface where the user hands SURE a value that
/// may be a credential in the same breath as the command that keeps it, and the
/// rule here would keep it verbatim under
/// `docs/architecture/PROJECT_INTENT.md`'s "minus nothing". `P15-T024` decided
/// the other way: this rule wins, the goal is redacted like every other accepted
/// document, and the report prints the text this leaves in the row rather than
/// the words that were typed. The reasons are in that document, which also
/// records the case against the choice.
///
/// It is written down here because the question comes back: a reader who finds
/// one document type exempt has to know whether the next one may be, and the
/// answer is that a door naming one channel is a door the next channel inherits.
/// The exception count is zero.
pub(crate) fn redact_document(value: &Value) -> Value {
    redact::redact_value(value)
}

/// How long to wait before asking again whether the file has become WAL yet.
///
/// Short, because the wait is for another process to finish a single page
/// write, and the loop is bounded by the caller's busy timeout rather than by a
/// count of attempts.
const JOURNAL_MODE_RETRY: Duration = Duration::from_millis(5);

/// Put the file in `wal` mode, waiting out whoever else is doing the same.
///
/// # Why this is not left to the busy handler
///
/// Every other lock in this module waits in SQLite's busy handler and comes back
/// after [`StoreOptions::busy_timeout`]. This one cannot: SQLite's own
/// documentation for `sqlite3_busy_handler` names the journal-mode change as a
/// case where it *declines* to invoke the handler, because waiting could
/// deadlock. Changing a rollback-journal database to WAL needs a moment of
/// exclusive access, and every other process doing the same thing gets
/// `SQLITE_BUSY` immediately.
///
/// That is the first moment a new user meets this store — several hooks firing
/// at once against a database that does not exist yet — and without this loop
/// five of six processes fail to open it. `sure-core/tests/store_concurrency.rs`
/// is what found it, and only because that test waits for all its processes to
/// arrive together; run one after another they never collide.
///
/// # What is not retried
///
/// The change, and only the change. Once the file is WAL the pragma returns the
/// current mode without touching a lock, so a second open never reaches the
/// loop. Writes are not retried at all — see the concurrency contract.
fn establish_journal_mode(
    connection: &Connection,
    path: &Path,
    wait: Duration,
) -> Result<String, StoreError> {
    let deadline = Instant::now() + wait;
    loop {
        // The mode that comes back is the mode the file actually got, which is
        // not always the one that was asked for: a filesystem that cannot do
        // WAL leaves it at `delete`, and SURE reports what it got rather than
        // what it wanted.
        let outcome = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0));
        match outcome {
            Ok(mode) => return Ok(mode),
            Err(error) if is_busy(&error) => {
                if Instant::now() >= deadline {
                    return Err(StoreError::Busy {
                        path: path.to_path_buf(),
                        waited_ms: wait.as_millis() as u64,
                    });
                }
                std::thread::sleep(JOURNAL_MODE_RETRY);
            }
            Err(error) => {
                return Err(StoreError::Open {
                    path: path.to_path_buf(),
                    message: error.to_string(),
                });
            }
        }
    }
}

impl HistoryFilter<'_> {
    /// The `WHERE` clause and its parameters.
    ///
    /// Built here rather than written out at each call site so that a filter
    /// cannot mean one thing for a read and another for a delete — which is the
    /// mistake that makes `sure history delete` remove more than `sure history`
    /// showed.
    fn sql(&self) -> (String, Vec<SqlValue>) {
        let mut conditions = Vec::new();
        let mut parameters = Vec::new();

        if let Some(fingerprint) = self.project_fingerprint {
            conditions.push("project_fingerprint = ?");
            parameters.push(SqlValue::Text(fingerprint.as_str().to_owned()));
        }
        if let Some(kind) = self.kind {
            conditions.push("kind = ?");
            parameters.push(SqlValue::Text(kind.as_str().to_owned()));
        }
        if !self.include_recordings {
            // The privacy default: full recordings are not part of history
            // unless a caller asked for them by name.
            conditions.push("kind <> ?");
            parameters.push(SqlValue::Text(RECORDING.to_owned()));
        }

        if conditions.is_empty() {
            (String::new(), parameters)
        } else {
            (format!(" WHERE {}", conditions.join(" AND ")), parameters)
        }
    }
}

/// Where the store tests put their scratch files.
///
/// `target/tmp`, git-ignored, on the same volume as the checkout. Derived from
/// the compiled location of this crate rather than the working directory, so a
/// test gives the same answer wherever it was started from.
#[cfg(test)]
pub(crate) fn scratch_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("target").join("tmp"))
        .unwrap_or_else(|| std::env::temp_dir().join("sure-store-tests"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;
    use sure_protocol::documents::DocumentKind;

    /// A path under `target/tmp`, which is git-ignored and on the same volume
    /// as the checkout.
    ///
    /// The name carries the process id, for the reason `store_concurrency.rs`
    /// records in full: freshness must not depend on a deletion succeeding, because
    /// on Windows a file another process holds cannot be deleted and the failure is
    /// easy to swallow. A unique name cannot be stale, so a directory a previous
    /// run left locked is simply not this run's directory. The clear that follows
    /// covers the one case uniqueness does not — a reused process id — and stops
    /// the test there, since that is the case where a stale database is readable.
    ///
    /// A residue worth knowing about: unique names accumulate one directory per
    /// test per run under `target/tmp`, which is disposable scratch space. The
    /// alternative was a name that is reused, which is the thing that lied.
    fn scratch(name: &str) -> PathBuf {
        let directory = crate::store::scratch_root().join(format!("{name}-{}", std::process::id()));
        match fs::remove_dir_all(&directory) {
            Ok(()) => {}
            // The ordinary case, and now the expected one.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!(
                "cannot clear {}: {error}. This process id was used before and its \
                 database is still on disk, so the assertions below could not tell it \
                 apart from this run's writes.",
                directory.display()
            ),
        }
        fs::create_dir_all(&directory).expect("a scratch directory");
        directory
    }

    fn store_in(name: &str) -> Store {
        Store::open_at(&scratch(name).join("sure.db")).expect("the store opens")
    }

    /// One real finding, the document a report is built from.
    ///
    /// Written out rather than built from a domain type on purpose: these tests
    /// are about storage, and a fixture that tracked every field the domain
    /// model gains would make a storage test fail for a reason that has nothing
    /// to do with storage. The documents' own conformance to their schemas is
    /// `crates/sure-protocol/tests/conformance.rs`'s subject.
    fn finding_document(explanation: &str) -> Value {
        json!({
            "id": "fnd_01j2m8q5aaaabbbbccccddddee",
            "title": "Email is reported as sent but nothing is sent",
            "severity": "must_fix",
            "status": "open",
            "explanation": explanation,
            "evidence": [],
            "assessment_source": "deterministic_check",
            "severity_rationale": "blocks_hand_off",
        })
    }

    /// One real claim, the document that records what the AI said it did.
    fn claim_document(assessment: &str) -> Value {
        json!({
            "id": "clm_01j2m8q5aaaabbbbccccddddee",
            "claim_text": "I added the retry logic and the tests pass",
            "assessment": assessment,
        })
    }

    #[test]
    fn a_stored_document_is_validated_before_it_is_written() {
        // A finding with no `status`. This is the check that keeps a malformed
        // record out of the file, where it would read back later as a record.
        let store = store_in("rejected");
        let error = store
            .append(RecordKind::Document(DocumentKind::Finding), &json!({}))
            .unwrap_err();
        match error {
            StoreError::Rejected { violations, .. } => {
                assert!(!violations.is_empty(), "no violations were reported");
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
        assert_eq!(store.count(&HistoryFilter::default()).unwrap(), 0);
    }

    #[test]
    fn a_valid_document_is_stored_and_read_back() {
        let store = store_in("roundtrip");
        let document = finding_document("the button is bound to a handler that is never called");
        let id = store
            .append(RecordKind::Document(DocumentKind::Finding), &document)
            .unwrap();
        assert!(id > 0);

        let records = store.history(&HistoryFilter::default(), 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, RecordKind::Document(DocumentKind::Finding));
        assert_eq!(records[0].document, document);
        assert_eq!(
            records[0].document_version,
            sure_protocol::DOCUMENT_VERSION,
            "the row was not stamped with the format this build writes"
        );
    }

    #[test]
    fn a_secret_in_a_document_does_not_reach_the_file() {
        // The claim is about the bytes, not about the value in memory, so it is
        // checked against the bytes: the store is closed first, which makes
        // SQLite checkpoint the write-ahead log back into the file.
        let directory = scratch("redaction");
        let path = directory.join("sure.db");
        let secret = "ghp_abcdefghijklmnopqrstuvwxyz012345";
        {
            let store = Store::open_at(&path).unwrap();
            store
                .append(
                    RecordKind::Document(DocumentKind::Finding),
                    &json!({
                        "id": "fnd_01j2m8q5aaaabbbbccccddddee",
                        "status": "open",
                        "severity": "must_fix",
                        "title": "the token leaked",
                        "explanation": "the client logged its authorization header",
                        "evidence": [{
                            "id": "evd_01j2m8q5aaaabbbbccccddddee",
                            "class": "observed_fact",
                            "summary": format!("the log line said token={secret}"),
                            "anchor": {
                                "subject": "file",
                                "location": "logs/auth.log",
                                "locator": "line 42"
                            },
                            "severity": "must_fix",
                        }],
                        "assessment_source": "observed_fact",
                        "severity_rationale": "blocks_hand_off",
                    }),
                )
                .unwrap();
        }

        for entry in fs::read_dir(&directory).unwrap() {
            let entry = entry.unwrap();
            let bytes = fs::read(entry.path()).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains(secret),
                "the secret survived in {}",
                entry.path().display()
            );
        }
    }

    #[test]
    fn redaction_leaves_the_documents_shape_alone() {
        // Why redacting before validating is safe: only string *contents* can
        // change, so a document that matched its schema still does.
        let document = json!({
            "status": "open",
            "severity": "must_fix",
            "count": 3,
            "flags": [true, false, null],
            "nested": {"title": "risk-free"},
        });
        let redacted = redact_document(&document);
        assert_eq!(redacted["count"], document["count"]);
        assert_eq!(redacted["flags"], document["flags"]);
        assert_eq!(redacted["nested"]["title"], json!("risk-free"));
        assert_eq!(redacted["status"], document["status"]);
    }

    #[test]
    fn a_recording_has_no_schema_but_must_still_be_an_object() {
        let store = store_in("recording");
        assert!(
            store
                .append_recording(&json!({"stdout": "hello"}), None)
                .is_ok()
        );
        match store.append_recording(&json!("just a string"), None) {
            Err(StoreError::Rejected { kind, .. }) => assert!(kind.is_recording()),
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    #[test]
    fn recordings_are_excluded_from_history_unless_asked_for() {
        // The privacy default, as a behaviour rather than a comment.
        let store = store_in("recordings_hidden");
        store
            .append_recording(&json!({"stdout": "x"}), None)
            .unwrap();
        store
            .append(
                RecordKind::Document(DocumentKind::Finding),
                &finding_document("a finding, so the history is not only recordings"),
            )
            .unwrap();

        assert_eq!(store.count(&HistoryFilter::default()).unwrap(), 1);
        let with = HistoryFilter {
            include_recordings: true,
            ..HistoryFilter::default()
        };
        assert_eq!(store.count(&with).unwrap(), 2);
        assert_eq!(store.count(&HistoryFilter::recordings()).unwrap(), 1);
    }

    #[test]
    fn deleting_recordings_leaves_the_rest_of_the_history() {
        // "Full recordings are clearly distinguishable and deletable."
        let store = store_in("delete_recordings");
        store
            .append_recording(&json!({"stdout": "x"}), None)
            .unwrap();
        store
            .append_recording(&json!({"stdout": "y"}), None)
            .unwrap();
        store
            .append(
                RecordKind::Document(DocumentKind::Finding),
                &finding_document("the rest of the history, which deleting recordings must spare"),
            )
            .unwrap();

        assert_eq!(store.delete_recordings().unwrap(), 2);
        assert_eq!(store.count(&HistoryFilter::recordings()).unwrap(), 0);
        assert_eq!(store.count(&HistoryFilter::default()).unwrap(), 1);
    }

    #[test]
    fn a_filter_means_the_same_thing_to_a_read_and_to_a_delete() {
        // The mistake this prevents: `delete` removing more than `history`
        // showed, because the two built their WHERE clauses separately.
        let store = store_in("filter_agreement");
        for _ in 0..3 {
            store
                .append_recording(&json!({"stdout": "x"}), None)
                .unwrap();
        }
        let fingerprint = FingerprintId::generate();
        store
            .append_for(
                RecordKind::Document(DocumentKind::Claim),
                &claim_document("cannot_confirm"),
                "C:\\work\\app",
                &fingerprint,
            )
            .unwrap();

        let only_mine = HistoryFilter::for_project(&fingerprint);
        assert_eq!(store.count(&only_mine).unwrap(), 1);
        assert_eq!(store.delete(&only_mine).unwrap(), 1);
        assert_eq!(store.count(&only_mine).unwrap(), 0);
        // The recordings were not touched: the filter never mentioned them.
        assert_eq!(store.count(&HistoryFilter::recordings()).unwrap(), 3);
    }

    #[test]
    fn a_record_carries_the_project_state_it_is_about() {
        let store = store_in("project_bound");
        let fingerprint = FingerprintId::generate();
        store
            .append_for(
                RecordKind::Document(DocumentKind::Claim),
                &claim_document("confirmed"),
                "C:\\work\\my project",
                &fingerprint,
            )
            .unwrap();

        let records = store.history(&HistoryFilter::default(), 10).unwrap();
        assert_eq!(
            records[0].project_root.as_deref(),
            Some("C:\\work\\my project")
        );
        assert_eq!(
            records[0].project_fingerprint.as_deref(),
            Some(fingerprint.as_str()),
            "a record that does not name its project state can be read against a later one"
        );
    }

    #[test]
    fn history_is_newest_first_and_unambiguous_within_a_millisecond() {
        // Several rows can share a millisecond — that is the normal case under
        // contention — so the order has to come from the identity and not from
        // whatever the query planner did.
        let store = store_in("ordering");
        for _ in 0..25 {
            store
                .append_recording(&json!({"stdout": "x"}), None)
                .unwrap();
        }
        let records = store
            .history(
                &HistoryFilter {
                    include_recordings: true,
                    ..HistoryFilter::default()
                },
                100,
            )
            .unwrap();
        assert_eq!(records.len(), 25);
        let ids: Vec<i64> = records.iter().map(|record| record.id).collect();
        let mut descending = ids.clone();
        descending.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(ids, descending, "the read order is not newest-first");

        // Run it twice: an unstable order is the failure this test exists for.
        let again = store
            .history(
                &HistoryFilter {
                    include_recordings: true,
                    ..HistoryFilter::default()
                },
                100,
            )
            .unwrap();
        assert_eq!(
            again.iter().map(|r| r.id).collect::<Vec<_>>(),
            ids,
            "the order changed between two identical reads"
        );
    }

    #[test]
    fn a_limit_of_zero_returns_nothing_rather_than_everything() {
        let store = store_in("limit_zero");
        store
            .append_recording(&json!({"stdout": "x"}), None)
            .unwrap();
        let filter = HistoryFilter {
            include_recordings: true,
            ..HistoryFilter::default()
        };
        assert!(store.history(&filter, 0).unwrap().is_empty());
        assert_eq!(store.count(&filter).unwrap(), 1);
    }

    #[test]
    fn an_unknown_kind_is_reported_rather_than_guessed_at() {
        // A row a newer SURE wrote. Reached by hand here because the write path
        // cannot produce it.
        let store = store_in("unknown_kind");
        store
            .append_recording(&json!({"stdout": "x"}), None)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE records SET kind = 'telemetry' WHERE kind = 'recording'",
                [],
            )
            .unwrap();

        match store.history(&HistoryFilter::default(), 10) {
            Err(StoreError::UnknownKind { name, .. }) => assert_eq!(name, "telemetry"),
            other => panic!("expected an unknown kind, got {other:?}"),
        }
    }

    #[test]
    fn a_damaged_row_is_reported_rather_than_skipped() {
        // Skipping it would return a history with a hole in it that looked
        // complete, which is the failure a history exists to prevent.
        //
        // Read with a filter that includes recordings, because the damaged row
        // is one: the default filter excludes them, so a read through it would
        // return an empty history and this test would pass without having asked
        // the question it means to ask.
        let store = store_in("damaged_row");
        store
            .append_recording(&json!({"stdout": "x"}), None)
            .unwrap();
        store
            .connection
            .execute("UPDATE records SET document = 'not json'", [])
            .unwrap();
        let filter = HistoryFilter {
            include_recordings: true,
            ..HistoryFilter::default()
        };
        match store.history(&filter, 10) {
            Err(StoreError::MalformedRow { .. }) => {}
            other => panic!("expected a malformed row, got {other:?}"),
        }
    }

    #[test]
    fn the_file_is_healthy_after_being_written_to() {
        let store = store_in("integrity");
        for _ in 0..10 {
            store
                .append_recording(&json!({"stdout": "x"}), None)
                .unwrap();
        }
        store.integrity_check().expect("a healthy file");
    }

    #[test]
    fn a_healthy_file_is_not_reported_as_damaged() {
        // `PRAGMA integrity_check` answers with one row, "ok". A check written
        // as "any problems listed" would pass on a file that returned nothing
        // at all, which is not the same as a healthy one.
        let store = store_in("integrity_ok");
        assert!(store.integrity_check().is_ok());
    }

    #[test]
    fn the_schema_is_at_the_version_this_build_writes() {
        let store = store_in("schema_version");
        assert_eq!(store.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    }

    #[test]
    fn the_journal_mode_is_reported_rather_than_assumed() {
        // WAL is what the read-concurrency half of the contract depends on, and
        // it is not always granted. Asserting it here would be a test that fails
        // on a network share; reporting it is what lets `sure doctor` say so.
        let store = store_in("journal_mode");
        assert_eq!(store.journal_mode().to_lowercase(), "wal");
    }

    #[test]
    fn opening_the_store_creates_only_its_own_directory() {
        let directory = scratch("creates_directory");
        let nested = directory.join("data").join("SURE").join("sure.db");
        assert!(!nested.parent().unwrap().exists());
        let store = Store::open_at(&nested).unwrap();
        assert!(nested.exists());
        assert_eq!(store.path(), nested.as_path());
    }
}
