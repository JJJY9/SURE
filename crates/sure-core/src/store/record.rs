//! What a stored row is, and what it takes to read one back.
//!
//! # The gap this closes
//!
//! `docs/architecture/PROTOCOL.md` records it as a known gap and
//! `docs/architecture/FROZEN_SEMANTICS.md` as conformance gap 3: the six
//! documents SURE writes carry no version, so a record written by a newer SURE
//! and read by an older one loses whatever fields the older build does not know.
//! The loss is silent. A finding that gained a `confidence` field would come
//! back without it and read as a finding that never had one.
//!
//! `crates/sure-protocol/tests/round_trip.rs` asserts that loss against bare
//! `serde`, deliberately, so it stays a recorded decision rather than an
//! accident of serde's defaults. This module is the fix, and the fix is not to
//! put a version inside the documents — `docs/architecture/PROTOCOL.md` says why
//! that is the wrong place. It is to put the version on the **record**, which is
//! the thing SURE controls end to end.
//!
//! So every row carries `document_version`, and [`StoredRecord::decode`] refuses
//! a row whose stamp is newer than [`sure_protocol::DOCUMENT_VERSION`]. Refusing
//! is the point: the alternative is a value that looks like a finding and is not
//! one, which is a wrong answer about a project rather than a visible error.
//! [`StoredRecord::document`] hands back the raw JSON for a caller that wants to
//! show it anyway, with the version right there to show alongside it.
//!
//! # Why a kind is not just a document kind
//!
//! [`RecordKind`] wraps [`DocumentKind`] rather than restating it, so the seven
//! schemas and the seven storable kinds cannot drift apart: there is one list, and
//! the eighth kind, [`RecordKind::Recording`], is the one thing SURE stores
//! that has no schema because it is not a statement about a project — it is raw
//! captured material, kept only under explicit opt-in
//! (`docs/security/PRIVACY.md`), and held to a different rule: it is excluded
//! from history unless a caller asks for it by name, and it can be deleted
//! without touching anything else.

use std::fmt;

use serde::de::DeserializeOwned;
use serde_json::Value;
use sure_protocol::documents::{self, DocumentKind};

use crate::store::error::StoreError;

/// The name [`RecordKind::Recording`] is stored under.
///
/// A constant rather than a literal so that the test which proves it does not
/// collide with a document name has something to compare against.
pub const RECORDING: &str = "recording";

/// The name [`RecordKind::Approval`] is stored under.
///
/// A constant for the same reason [`RECORDING`] is one: the test that proves no
/// document is called this has to compare against something.
pub const APPROVAL: &str = "approval";

/// The name [`RecordKind::Allowance`] is stored under.
///
/// A constant for the same reason the other two are.
pub const ALLOWANCE: &str = "allowance";

/// The name [`RecordKind::Decision`] is stored under.
///
/// A constant for the same reason the other four are.
pub const DECISION: &str = "decision";

/// The name [`RecordKind::Acknowledgement`] is stored under.
///
/// A constant for the same reason the other five are.
pub const ACKNOWLEDGEMENT: &str = "acknowledgement";

/// One thing the store can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    /// One of the documents with a schema in `schemas/`.
    Document(DocumentKind),
    /// Raw captured material: a prompt, an agent response, terminal output.
    ///
    /// Stored only under explicit opt-in, excluded from history by default, and
    /// deletable on its own. `docs/security/PRIVACY.md` is the rule; this type
    /// is what makes the rule expressible.
    Recording,
    /// A recorded approval to run project commands on this machine.
    ///
    /// **The third shape a stored row can have, and it is not a document.**
    /// `ADR 0009` makes host execution conditional on *recorded per-command
    /// consent*, and `P3-T006`'s second acceptance sentence makes the state of
    /// that consent auditable locally. Neither of those is satisfied by a value
    /// that lives only as long as the process that built it, so the record has
    /// to be written down — and writing it down as a document would put it in
    /// the integration protocol, which is a contract with harnesses rather than
    /// a place for SURE's own audit trail.
    ///
    /// It is kept in history rather than excluded from it, unlike a recording.
    /// A consent is a statement about what SURE was allowed to do to a project,
    /// it names the project state it was given for, and a user asking *what has
    /// SURE been allowed to run here* is asking the question this row exists to
    /// answer. It is still deletable, because `docs/security/PRIVACY.md` gives
    /// the user the whole local history and not a part of it.
    Approval,
    /// A recorded one-time allowance: the user's answer to a protection block.
    ///
    /// **The fourth shape a stored row can have, and it is not an approval.**
    /// `P13-T005`'s acceptance is that a broad delete, a force push and a
    /// sensitive read are represented *with a one-time override path*: the user
    /// can say "SURE would let this one through, once". The hook is a fresh
    /// process per event, so the grant cannot live in memory, and an
    /// [`Self::Approval`] is the wrong row for it — that kind's reader decodes
    /// every row of it as one [`HostConsent`], so a second document shape under
    /// the same name would make the approval audit trail stop reading rather
    /// than skip what it does not understand. Two statements, two kinds.
    ///
    /// It is kept in history rather than excluded from it, for the same reason
    /// an approval is: *what has SURE been allowed to do here* is the question
    /// this row exists to answer, and a permission nobody can read back is not
    /// auditable. [`crate::allowance`] is what is in the document.
    Allowance,
    /// A protection decision SURE reached about one request.
    ///
    /// **The fifth shape a stored row can have, and it is a stale one if nothing
    /// writes it.** `P13-T006`'s acceptance is that a warn, a block and an allow
    /// that came from a one-time allowance are recorded locally without secrets,
    /// and `P13-T005` wrote the vocabulary for the verdict and the danger. What
    /// was missing is a row: the decision lived only as long as the process that
    /// took it, so after the hook exited it did not exist anywhere.
    /// [`crate::protection_history`] is what is in the document, and
    /// `SessionEventStore::persist_decision` is the one writer.
    ///
    /// Its kind is its own rather than [`Self::Allowance`]'s or
    /// [`Self::Approval`]'s for the reason those two are apart: each kind's
    /// reader decodes every row of it as one shape, so a second shape under one
    /// name stops the audit trail instead of skipping what it does not know. A
    /// decision is also not a *statement about a project state* the way an
    /// approval is — it is about one request, and it hangs from the event that
    /// request produced.
    Decision,
    /// A person's recorded decision to live with one finding (ADR 0019).
    ///
    /// **The sixth shape, and the first one that answers a finding.** A candidate
    /// finding — one no check can settle — stays visible in every report, and
    /// without a place for the person's verification to go, the run would read
    /// `needs_attention` forever. This row is that place: it names the finding's
    /// cross-run identity (title, anchor location, locator), the finding id it
    /// was made from, a required reason and when it was made.
    /// [`crate::acknowledgement`] is what is in the document.
    ///
    /// Its own kind rather than a [`Self::Decision`] for the reason above: the
    /// two readers decode different shapes, and an acceptance is not about a
    /// protected request. It is written to the **user-level** store and never to
    /// the checked project, because the project is editable by the agent whose
    /// work is being judged (ADR 0011).
    Acknowledgement,
}

impl RecordKind {
    /// Every storable kind, documents first.
    ///
    /// [`DocumentKind::FixtureExpectation`] is deliberately absent: a fixture
    /// expectation describes what an evaluation run must produce, it is read
    /// from `fixtures/`, and it is never a record about the user's project.
    pub const ALL: &[RecordKind] = &[
        RecordKind::Document(DocumentKind::Event),
        RecordKind::Document(DocumentKind::Finding),
        RecordKind::Document(DocumentKind::Claim),
        RecordKind::Document(DocumentKind::CheckResult),
        RecordKind::Document(DocumentKind::ProjectIntent),
        RecordKind::Document(DocumentKind::Repair),
        RecordKind::Document(DocumentKind::RepairEnvelope),
        RecordKind::Recording,
        RecordKind::Approval,
        RecordKind::Allowance,
        RecordKind::Decision,
        RecordKind::Acknowledgement,
    ];

    /// The stable name, used as the value of the `kind` column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Document(kind) => kind.as_str(),
            Self::Recording => RECORDING,
            Self::Approval => APPROVAL,
            Self::Allowance => ALLOWANCE,
            Self::Decision => DECISION,
            Self::Acknowledgement => ACKNOWLEDGEMENT,
        }
    }

    /// The kind with this name, if it is one SURE knows.
    ///
    /// Returns `None` rather than a default: a row whose kind this build does
    /// not recognise is a row it cannot describe, and pretending otherwise
    /// would put an unknown record into a report under a name that means
    /// something else.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        if name == RECORDING {
            return Some(Self::Recording);
        }
        if name == APPROVAL {
            return Some(Self::Approval);
        }
        if name == ALLOWANCE {
            return Some(Self::Allowance);
        }
        if name == DECISION {
            return Some(Self::Decision);
        }
        if name == ACKNOWLEDGEMENT {
            return Some(Self::Acknowledgement);
        }
        documents::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == name)
            .map(Self::Document)
    }

    /// The document this kind stores, if it stores one.
    ///
    /// A recording, an approval, an allowance, a decision and an acknowledgement
    /// have no schema, and this is where that shows: there is nothing to
    /// validate them against, which is why the write path treats them separately
    /// rather than as a document with a missing schema. **The absence is not a
    /// gap — none of the five is a statement about a project in the protocol's
    /// sense.** A recording is not a statement at all; an approval, an
    /// allowance, a decision and an acknowledgement are statements about SURE's
    /// own behaviour, authority and the user's own decisions, which
    /// `sure-protocol` does not describe.
    #[must_use]
    pub const fn document(self) -> Option<DocumentKind> {
        match self {
            Self::Document(kind) => Some(kind),
            Self::Recording
            | Self::Approval
            | Self::Allowance
            | Self::Decision
            | Self::Acknowledgement => None,
        }
    }

    /// Whether this is raw captured material rather than a statement.
    #[must_use]
    pub const fn is_recording(self) -> bool {
        matches!(self, Self::Recording)
    }

    /// Whether this is a recorded approval rather than a document.
    #[must_use]
    pub const fn is_approval(self) -> bool {
        matches!(self, Self::Approval)
    }

    /// Whether this is a recorded one-time allowance rather than a document.
    #[must_use]
    pub const fn is_allowance(self) -> bool {
        matches!(self, Self::Allowance)
    }

    /// Whether this is a recorded protection decision rather than a document.
    #[must_use]
    pub const fn is_decision(self) -> bool {
        matches!(self, Self::Decision)
    }

    /// Whether this is a recorded acceptance of one finding rather than a
    /// document.
    #[must_use]
    pub const fn is_acknowledgement(self) -> bool {
        matches!(self, Self::Acknowledgement)
    }

    /// Whether SURE will write this as a record about a project.
    ///
    /// False for exactly one kind: [`DocumentKind::FixtureExpectation`]
    /// describes what an evaluation run must produce, it is read from
    /// `fixtures/`, and storing it would put an expectation into a user's
    /// history under a name that reads like a result. [`RecordKind::ALL`]
    /// leaves it out, and [`crate::store::Store::append`] refuses it, so the
    /// claim is enforced rather than merely intended.
    #[must_use]
    pub const fn is_storable(self) -> bool {
        !matches!(self, Self::Document(DocumentKind::FixtureExpectation))
    }
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row, as it was read out of the store.
///
/// The fields are public because a report has to render them and there is
/// nothing here that a caller could corrupt: the value is a copy of what was
/// stored, and changing the copy cannot reach the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    /// The row's identity. Stable for the life of the file — see the
    /// `AUTOINCREMENT` note in `sql/0001_records.sql`.
    pub id: i64,
    /// What kind of record this is.
    pub kind: RecordKind,
    /// The document format the row was written in.
    pub document_version: u32,
    /// When it was written, as milliseconds since the epoch.
    pub written_at_ms: i64,
    /// The project root it is about, as text, if it is about a project.
    ///
    /// Text rather than a `PathBuf` on purpose: it records where the project
    /// *was*, which may be a Windows path read on Linux or a directory that no
    /// longer exists. Reconstructing it as a live path would invite a caller to
    /// use it as one.
    pub project_root: Option<String>,
    /// The project state it is about, if it is about a project.
    ///
    /// `docs/architecture/EVIDENCE_MODEL.md`: evidence whose fingerprint
    /// differs from the current one is stale. Recording the fingerprint beside
    /// the record is what lets a reader tell rather than assume.
    pub project_fingerprint: Option<String>,
    /// The document itself.
    pub document: Value,
}

impl StoredRecord {
    /// Whether this row was written by a build that knew more than this one.
    ///
    /// A row can be *older* and be perfectly readable; only newer is a problem,
    /// because only newer means fields are present that this build will drop.
    #[must_use]
    pub fn is_from_a_newer_build(&self) -> bool {
        self.document_version > sure_protocol::DOCUMENT_VERSION
    }

    /// Read the document as the type this build knows.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NewerDocument`] when the row is stamped with a
    /// document version this build does not know, and [`StoreError::Decode`]
    /// when the document does not have the shape the type expects. The two are
    /// kept apart because they mean different things: the first is "SURE is too
    /// old to read this", the second is "this row is damaged".
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, StoreError> {
        if self.is_from_a_newer_build() {
            return Err(StoreError::NewerDocument {
                kind: self.kind,
                found: self.document_version,
                supported: sure_protocol::DOCUMENT_VERSION,
            });
        }
        serde_json::from_value(self.document.clone()).map_err(|error| StoreError::Decode {
            kind: self.kind,
            id: self.id,
            message: error.to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_storable_kind_has_a_distinct_name() {
        let names: BTreeSet<_> = RecordKind::ALL.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(names.len(), RecordKind::ALL.len());
    }

    #[test]
    fn the_name_of_a_recording_is_not_the_name_of_any_document() {
        // If a future document were called "recording", a row written as one
        // would read back as the other, and `from_name` would silently pick
        // whichever came first.
        for &kind in documents::ALL {
            assert_ne!(kind.as_str(), RECORDING);
        }
    }

    #[test]
    fn the_name_of_an_approval_is_not_the_name_of_any_document_either() {
        for &kind in documents::ALL {
            assert_ne!(kind.as_str(), APPROVAL);
        }
        assert_ne!(APPROVAL, RECORDING);
    }

    #[test]
    fn the_name_of_an_allowance_is_the_name_of_nothing_else() {
        // Four schema-less kinds share one column, and `from_name` picks by
        // name: two of them called the same thing would read back as whichever
        // came first in the match.
        for &kind in documents::ALL {
            assert_ne!(kind.as_str(), ALLOWANCE);
        }
        assert_ne!(ALLOWANCE, RECORDING);
        assert_ne!(ALLOWANCE, APPROVAL);
        assert_ne!(ALLOWANCE, DECISION);
    }

    #[test]
    fn the_name_of_a_decision_is_the_name_of_nothing_else() {
        // The same rule again for the fourth name, because `from_name` is what
        // turns a row's `kind` column back into a kind, and a collision would
        // make a decision read as an allowance rather than as a row nothing
        // understands. `"decision"` is the word a person would reach for, so it
        // is also the one most likely to be chosen for something else later.
        for &kind in documents::ALL {
            assert_ne!(kind.as_str(), DECISION);
        }
        assert_ne!(DECISION, RECORDING);
        assert_ne!(DECISION, APPROVAL);
        assert_ne!(DECISION, ALLOWANCE);
    }

    #[test]
    fn a_decision_is_kept_in_history_rather_than_kept_out_of_it() {
        // A verdict is the thing a user asks the history for, so a kind the
        // default filter excluded would be an audit trail nobody could read —
        // the failure mode `P13-T006` names, where the row exists and never
        // answers anything.
        assert!(!RecordKind::Decision.is_recording());
        assert!(!RecordKind::Decision.is_approval());
        assert!(!RecordKind::Decision.is_allowance());
        assert!(RecordKind::Decision.is_decision());
        assert!(RecordKind::Decision.is_storable());
        assert!(RecordKind::Decision.document().is_none());

        let filter = crate::store::HistoryFilter::default();
        assert!(
            !filter.include_recordings,
            "the default filter is the privacy default, and it excludes recordings only"
        );
    }

    #[test]
    fn an_allowance_is_stored_in_history_rather_than_kept_out_of_it() {
        // The same rule an approval is held to, for the same reason: a
        // permission the user granted is a statement about what SURE was
        // allowed to do, and the command a user would look in has to show it.
        assert!(!RecordKind::Allowance.is_recording());
        assert!(!RecordKind::Allowance.is_approval());
        assert!(RecordKind::Allowance.is_allowance());
        assert!(RecordKind::Allowance.is_storable());
        assert!(RecordKind::Allowance.document().is_none());
    }

    #[test]
    fn an_approval_is_stored_in_history_rather_than_kept_out_of_it() {
        // The opposite of a recording, and the difference is the point. A
        // recording is private material the user opted into; an approval is a
        // statement about what SURE was allowed to do, and the sentence this
        // kind exists for is that the state of those approvals is auditable.
        // A kind that `HistoryFilter::default` excludes would make the audit
        // trail invisible to the command a user would look in.
        assert!(!RecordKind::Approval.is_recording());
        assert!(RecordKind::Approval.is_approval());
        assert!(RecordKind::Approval.is_storable());
        assert!(RecordKind::Approval.document().is_none());

        let filter = crate::store::HistoryFilter::default();
        assert!(
            !filter.include_recordings,
            "the default filter is the privacy default, and it excludes recordings only"
        );
    }

    #[test]
    fn the_storable_documents_are_every_document_except_the_fixture_schema() {
        // The drift guard. A document gaining a schema and no way to be stored
        // — or a stored kind with no schema to check it — shows up here rather
        // than at the first write.
        let storable: BTreeSet<DocumentKind> = RecordKind::ALL
            .iter()
            .filter_map(|kind| kind.document())
            .collect();
        let expected: BTreeSet<DocumentKind> = documents::ALL
            .iter()
            .copied()
            .filter(|kind| *kind != DocumentKind::FixtureExpectation)
            .collect();
        assert_eq!(storable, expected);
    }

    #[test]
    fn every_kind_survives_its_own_name() {
        for &kind in RecordKind::ALL {
            assert_eq!(RecordKind::from_name(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn an_unknown_name_is_not_guessed_at() {
        // A row written by a newer SURE is the realistic source of this. The
        // answer has to be "unknown", not "the first kind".
        assert_eq!(RecordKind::from_name("telemetry"), None);
        assert_eq!(RecordKind::from_name(""), None);
        assert_eq!(RecordKind::from_name("FINDING"), None);
    }

    #[test]
    fn the_name_of_an_acknowledgement_is_the_name_of_nothing_else() {
        // The same rule as the four names above. `"acknowledgement"` is the
        // word a person would reach for, which is exactly why it has to be
        // checked against every name that already exists.
        for &kind in documents::ALL {
            assert_ne!(kind.as_str(), ACKNOWLEDGEMENT);
        }
        assert_ne!(ACKNOWLEDGEMENT, RECORDING);
        assert_ne!(ACKNOWLEDGEMENT, APPROVAL);
        assert_ne!(ACKNOWLEDGEMENT, ALLOWANCE);
        assert_ne!(ACKNOWLEDGEMENT, DECISION);
    }

    #[test]
    fn only_the_five_recorded_kinds_lack_a_schema() {
        // The drift guard, and it has already done its job four times: adding
        // `Approval` broke the version of this test that said `is_recording`,
        // adding `Allowance` broke the version that said two, adding `Decision`
        // broke the version that said three, and adding `Acknowledgement` broke
        // the version that said four. What it now pins is that the schema-less
        // kinds are exactly the five that were chosen rather than the five that
        // happened to be there.
        for &kind in RecordKind::ALL {
            assert_eq!(
                kind.document().is_none(),
                kind.is_recording()
                    || kind.is_approval()
                    || kind.is_allowance()
                    || kind.is_decision()
                    || kind.is_acknowledgement(),
                "{kind} disagrees with itself about whether it has a schema"
            );
        }
        assert_eq!(
            RecordKind::ALL
                .iter()
                .filter(|kind| kind.document().is_none())
                .count(),
            5,
            "a sixth schema-less kind arrived without this test being read"
        );
    }

    #[test]
    fn a_row_from_a_newer_build_is_refused_rather_than_decoded() {
        let row = StoredRecord {
            id: 1,
            kind: RecordKind::Document(DocumentKind::Finding),
            document_version: sure_protocol::DOCUMENT_VERSION + 1,
            written_at_ms: 0,
            project_root: None,
            project_fingerprint: None,
            document: serde_json::json!({"status": "open"}),
        };
        assert!(row.is_from_a_newer_build());
        match row.decode::<Value>() {
            Err(StoreError::NewerDocument {
                found,
                supported,
                kind,
            }) => {
                assert_eq!(found, sure_protocol::DOCUMENT_VERSION + 1);
                assert_eq!(supported, sure_protocol::DOCUMENT_VERSION);
                assert_eq!(kind, RecordKind::Document(DocumentKind::Finding));
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // The value is still reachable, so `sure history` can print the row
        // with a caveat instead of hiding it.
        assert_eq!(row.document["status"], "open");
    }

    #[test]
    fn a_row_from_this_build_or_an_older_one_is_read() {
        for version in 1..=sure_protocol::DOCUMENT_VERSION {
            let row = StoredRecord {
                id: 1,
                kind: RecordKind::Document(DocumentKind::Claim),
                document_version: version,
                written_at_ms: 0,
                project_root: None,
                project_fingerprint: None,
                document: serde_json::json!({"text": "done"}),
            };
            assert!(
                !row.is_from_a_newer_build(),
                "version {version} was refused"
            );
            let value: Value = row.decode().expect("readable");
            assert_eq!(value["text"], "done");
        }
    }

    #[test]
    fn a_damaged_row_is_reported_as_damaged_rather_than_as_too_new() {
        // The two failures have different fixes — update SURE, versus the file
        // is wrong — so they must not arrive as the same error.
        // The field is what makes the decode fail; nothing reads it afterwards,
        // and `dead_code` is about reading rather than about existing.
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Status {
            status: u8,
        }
        let row = StoredRecord {
            id: 7,
            kind: RecordKind::Document(DocumentKind::CheckResult),
            document_version: sure_protocol::DOCUMENT_VERSION,
            written_at_ms: 0,
            project_root: None,
            project_fingerprint: None,
            document: serde_json::json!({"status": "not a number"}),
        };
        match row.decode::<Status>().unwrap_err() {
            StoreError::Decode { id, .. } => assert_eq!(id, 7),
            other => panic!("expected a decode failure, got {other:?}"),
        }
    }
}
