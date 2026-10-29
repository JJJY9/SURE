//! A person's recorded decision to live with a finding SURE could not settle
//! (ADR 0019).
//!
//! # What this module is, and what it is not
//!
//! Some findings can never be settled by a check: a `status: 200,` a scanner
//! matched in an OpenAI-compatible bridge, the word `mock` in a doc comment. ADR
//! 0018 keeps those findings out of repair contracts — correctly — but the
//! person's verification had nowhere to go, so the run stayed `needs_attention`
//! forever. This module is the place it goes: a row in the **user-level** store
//! naming the finding's cross-run identity
//! ([`FindingKey`](crate::recheck_lifecycle::FindingKey)), the finding id it was
//! made from, a required reason and when it was made.
//!
//! **The record is a decision, not evidence about the project.** It never
//! renders as proof that the code is correct; a matching finding keeps its
//! evidence, its severity and its place in the report, and changes status to
//! `AcceptedRisk` so the reader can tell SURE's uncertainty from the person's
//! answer to it.
//!
//! # Why it lives outside the project
//!
//! The checked project is editable by the agent whose work is being judged. A
//! project file that could silence a candidate would be a bypass of the thing
//! SURE exists to prevent (ADR 0011), so the record is written to the store —
//! the same boundary that keeps approvals and allowances out of a project's
//! reach.
//!
//! # Why the identity is the re-check's key
//!
//! The record names what [`FindingKey`](crate::recheck_lifecycle::FindingKey)
//! names: the title, the anchor location and the anchor locator. If the evidence
//! changes — the matched line moves or its text changes, the title changes — the
//! key no longer matches and the finding comes back as unresolved. An
//! acknowledgement is a statement about evidence SURE saw, not a permission for
//! a file. A finding with no checkable anchor cannot be bound that way at all,
//! and [`acknowledge`] refuses it rather than holding it by title alone.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sure_domain::finding::Finding;
use sure_domain::ids::FingerprintId;

use crate::diagnostics::Timestamp;
use crate::paths::compare::CaseSensitivity;
use crate::recheck_lifecycle::{FindingKey, HISTORY_SCAN_LIMIT, case_rule_for, same_project_root};
use crate::store::{HistoryFilter, RecordKind, Store, StoreError};

/// How many acknowledgement rows one read walks.
///
/// The same bound and the same refusal direction as
/// [`HISTORY_SCAN_LIMIT`]: the query is newest-first, the project filter runs in
/// Rust, and a truncated read would answer *what has been accepted here* with a
/// list that stopped early — the one wrong answer this reader must not give. One
/// person's recorded decisions are far fewer than a store's finding rows, so
/// reaching it is a damaged or shared store rather than an ordinary one.
const ACKNOWLEDGEMENT_SCAN_LIMIT: usize = HISTORY_SCAN_LIMIT;

/// Why an acknowledgement could not be recorded, read or removed.
#[derive(Debug)]
pub enum AcknowledgementError {
    /// The finding's evidence could carry a `must_fix`; it is a defect to fix,
    /// not a risk to accept (ADR 0019's first rule).
    NotAcknowledgeable,
    /// The finding has no checkable anchor, so the decision could not be bound
    /// to evidence that can change.
    NotBindable,
    /// No reason was given. A decision without a why is not auditable.
    NoReason,
    /// The read reached [`ACKNOWLEDGEMENT_SCAN_LIMIT`] with more rows behind
    /// it, so the answer would be truncated. Refused rather than answered
    /// short, in the direction `HISTORY_SCAN_LIMIT` documents.
    ScanStoppedEarly {
        /// The bound that was reached.
        limit: usize,
    },
    /// The store refused the read or the write.
    Store(StoreError),
}

impl fmt::Display for AcknowledgementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAcknowledgeable => f.write_str(
                "this finding's evidence can carry a must-fix, so it is a defect to fix rather \
                 than a risk to accept",
            ),
            Self::NotBindable => f.write_str(
                "this finding has no checkable anchor, so there is nothing an acceptance could be \
                 bound to; it would outlive the evidence it was made about",
            ),
            Self::NoReason => f.write_str(
                "an acceptance needs a reason: it is a decision someone may have to read later",
            ),
            Self::ScanStoppedEarly { limit } => write!(
                f,
                "the acknowledgement history holds more than {limit} rows and the read stopped \
                 at that bound; nothing was answered from a truncated list"
            ),
            Self::Store(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AcknowledgementError {}

impl From<StoreError> for AcknowledgementError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// One recorded acceptance, as it is written and read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acknowledgement {
    /// The finding's title — the first part of its cross-run identity.
    pub title: String,
    /// The anchor's location — the second part.
    pub location: String,
    /// The anchor's locator — the third part.
    pub locator: String,
    /// The finding id the decision was made from, kept for the audit trail.
    pub finding_id: String,
    /// Why the person accepted it.
    pub reason: String,
    /// When the decision was made, on the store's clock.
    pub recorded_at_ms: i64,
}

/// A recorded acceptance and the store row it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedAcknowledgement {
    /// The row id, which `sure acknowledge --undo` takes.
    pub row: i64,
    /// What the row holds.
    pub acknowledgement: Acknowledgement,
}

impl RecordedAcknowledgement {
    /// The identity this record matches findings by, under `case`.
    ///
    /// The stored parts are already normalised by the case rule in force when
    /// they were written; every stored identity is folded by that rule, so a
    /// reader that keeps the same rule for the current run's findings gets the
    /// same key. Nothing is folded here again — [`CaseSensitivity::Sensitive`]
    /// trims and keeps case, which is what an already-normalised value wants.
    fn key(&self) -> FindingKey {
        let a = &self.acknowledgement;
        FindingKey::from_parts(
            &a.title,
            &a.location,
            &a.locator,
            CaseSensitivity::Sensitive,
        )
    }
}

/// A finding as a report shows it, sufficient to name its identity.
///
/// The report path's input (ADR 0019): a `sure check` run records nothing, so a
/// person who just read its report has no store row to point at — what they have
/// is the report's own finding id, title and first evidence anchor. The caller
/// establishes *may this be accepted* from the report's `acknowledgeable` field,
/// which the run computed from [`Finding::can_be_acknowledged`]; the pipeline
/// re-checks it when the acceptance is applied, so a caller that got this wrong
/// records a row that never matches rather than one that closes a settled
/// finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedFinding {
    /// The finding id the report printed.
    pub finding_id: String,
    /// The finding's title, as the run rendered it.
    pub title: String,
    /// The first checkable evidence anchor's location, as the run rendered it.
    pub location: String,
    /// The same anchor's locator.
    pub locator: String,
}

/// Record that a person reviewed `finding` and accepted the risk.
///
/// # Errors
///
/// [`AcknowledgementError`]: the finding may not be accepted, has no checkable
/// anchor, no reason was given, or the store refused the write.
pub fn acknowledge(
    store: &Store,
    project_root: &str,
    fingerprint: &FingerprintId,
    finding: &Finding,
    reason: &str,
    case: CaseSensitivity,
) -> Result<RecordedAcknowledgement, AcknowledgementError> {
    if !finding.can_be_acknowledged() {
        return Err(AcknowledgementError::NotAcknowledgeable);
    }
    let key = FindingKey::from_finding(finding, case).ok_or(AcknowledgementError::NotBindable)?;
    let (title, location, locator) = key.parts();
    write(
        store,
        project_root,
        fingerprint,
        title,
        location,
        locator,
        finding.id.as_str(),
        reason,
        case,
    )
}

/// The same, for a finding the caller read out of a report (ADR 0019).
///
/// The identity is normalised under `case`, exactly as the run that rendered the
/// report normalised it, so the row matches the next run's finding. Whether the
/// finding may be accepted is the caller's claim here — the report's own
/// `acknowledgeable` field — and the pipeline re-checks it at application.
///
/// # Errors
///
/// [`AcknowledgementError`]: no reason was given or the store refused the write.
pub fn acknowledge_reported(
    store: &Store,
    project_root: &str,
    fingerprint: &FingerprintId,
    reported: &ReportedFinding,
    reason: &str,
    case: CaseSensitivity,
) -> Result<RecordedAcknowledgement, AcknowledgementError> {
    write(
        store,
        project_root,
        fingerprint,
        &reported.title,
        &reported.location,
        &reported.locator,
        &reported.finding_id,
        reason,
        case,
    )
}

/// The one write both entry points end in.
#[allow(
    clippy::too_many_arguments,
    reason = "the three identity parts, the id, the reason and the project are the row, \
              spelled out so the two entry points cannot pass a different subset"
)]
fn write(
    store: &Store,
    project_root: &str,
    fingerprint: &FingerprintId,
    title: &str,
    location: &str,
    locator: &str,
    finding_id: &str,
    reason: &str,
    case: CaseSensitivity,
) -> Result<RecordedAcknowledgement, AcknowledgementError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AcknowledgementError::NoReason);
    }
    // Normalised under the run's own rule, so a row written from a report and a
    // finding the next run derives arrive at the same key.
    let key = FindingKey::from_parts(title, location, locator, case);
    let (title, location, locator) = key.parts();
    let acknowledgement = Acknowledgement {
        title: title.to_owned(),
        location: location.to_owned(),
        locator: locator.to_owned(),
        finding_id: finding_id.to_owned(),
        reason: reason.to_owned(),
        recorded_at_ms: Timestamp::now().as_millis(),
    };
    let document = serde_json::to_value(&acknowledgement).map_err(|error| {
        AcknowledgementError::Store(StoreError::MalformedRow {
            id: 0,
            message: error.to_string(),
        })
    })?;
    let row = store.append_for(
        RecordKind::Acknowledgement,
        &document,
        project_root,
        fingerprint,
    )?;
    Ok(RecordedAcknowledgement {
        row,
        acknowledgement,
    })
}

/// Every acknowledgement recorded for this project, newest first.
///
/// Unlike [`AcknowledgementIndex`], this does not collapse re-acknowledgements:
/// a person asking *what have I accepted here* is owed the rows, and the list
/// command shows them as they were written.
///
/// # Errors
///
/// [`AcknowledgementError`]: the read reached its bound or the store refused it.
pub fn recorded(
    store: &Store,
    project_root: &str,
) -> Result<Vec<RecordedAcknowledgement>, AcknowledgementError> {
    let filter = HistoryFilter {
        project_fingerprint: None,
        kind: Some(RecordKind::Acknowledgement),
        include_recordings: false,
    };
    let rows = store.history(&filter, ACKNOWLEDGEMENT_SCAN_LIMIT)?;
    if rows.len() >= ACKNOWLEDGEMENT_SCAN_LIMIT {
        return Err(AcknowledgementError::ScanStoppedEarly {
            limit: ACKNOWLEDGEMENT_SCAN_LIMIT,
        });
    }
    let mut records = Vec::new();
    for row in rows {
        if !row
            .project_root
            .as_deref()
            .is_some_and(|root| same_project_root(root, project_root, case_rule_for(project_root)))
        {
            continue;
        }
        records.push(decode(&row)?);
    }
    Ok(records)
}

/// Remove one acknowledgement row, if it is one and it belongs to this project.
///
/// Returns whether a row was deleted. A row id that names another kind or
/// another project is refused by answering `false` — the caller reports that
/// nothing was removed rather than pretending it was.
///
/// # Errors
///
/// [`AcknowledgementError::Store`] if the read or the write failed.
pub fn undo(store: &Store, project_root: &str, row: i64) -> Result<bool, AcknowledgementError> {
    let Some(stored) = store.record(row)? else {
        return Ok(false);
    };
    if stored.kind != RecordKind::Acknowledgement {
        return Ok(false);
    }
    if !stored
        .project_root
        .as_deref()
        .is_some_and(|root| same_project_root(root, project_root, case_rule_for(project_root)))
    {
        return Ok(false);
    }
    Ok(store.delete_record_of_kind(row, RecordKind::Acknowledgement)?)
}

/// The acknowledgements recorded for one project, indexed by the identity they
/// match findings by.
///
/// A later acceptance of the same identity supersedes an earlier one: the read
/// is newest-first and the first row for a key wins, which is what makes
/// re-acknowledging after a review a replacement rather than a duplicate.
#[derive(Debug, Default)]
pub struct AcknowledgementIndex {
    entries: HashMap<FindingKey, RecordedAcknowledgement>,
}

impl AcknowledgementIndex {
    /// Read this project's acknowledgements.
    ///
    /// # Errors
    ///
    /// [`AcknowledgementError`]: the read reached its bound or the store
    /// refused it.
    pub fn load(store: &Store, project_root: &str) -> Result<Self, AcknowledgementError> {
        let mut index = Self::default();
        for recorded in recorded(store, project_root)? {
            // Newest first, so the first row for a key is the one that stands.
            index.entries.entry(recorded.key()).or_insert(recorded);
        }
        Ok(index)
    }

    /// The acceptance that covers `finding`, if one does.
    ///
    /// A finding with no checkable anchor matches nothing: its identity could
    /// not be written down in the first place ([`acknowledge`] refuses those).
    #[must_use]
    pub fn for_finding(
        &self,
        finding: &Finding,
        case: CaseSensitivity,
    ) -> Option<&RecordedAcknowledgement> {
        let key = FindingKey::from_finding(finding, case)?;
        self.entries.get(&key)
    }

    /// Whether anything was recorded at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Decode one stored acknowledgement row.
///
/// A row that cannot be read stops the read rather than being skipped —
/// [`crate::allowance`]'s rule: a row SURE cannot read is a row whose state it
/// does not know, and reading that hole as "no acceptance was recorded here"
/// would resurface the finding with no explanation.
fn decode(
    row: &crate::store::StoredRecord,
) -> Result<RecordedAcknowledgement, AcknowledgementError> {
    debug_assert!(
        row.kind == RecordKind::Acknowledgement,
        "the query asked for one kind and got another"
    );
    let acknowledgement: Acknowledgement = row.decode()?;
    Ok(RecordedAcknowledgement {
        row: row.id,
        acknowledgement,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sure_domain::evidence::{AnchorSubject, Evidence, EvidenceAnchor, EvidenceClass};
    use sure_domain::finding::{AssessmentSource, FindingBuilder, SeverityRationale};
    use sure_domain::severity::Severity;

    fn store_in(name: &str) -> Store {
        let dir = crate::store::scratch_root().join(format!("{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Store::open_at(&dir.join("store.db")).unwrap()
    }

    fn fingerprint() -> FingerprintId {
        FingerprintId::generate()
    }

    fn candidate(line: &str) -> Finding {
        FindingBuilder::new(
            AssessmentSource::DeterministicCheck,
            SeverityRationale::BlocksHandOff,
        )
        .title("project contains hard-coded success responses in production code")
        .severity(Severity::MustFix)
        .status(sure_domain::finding::FindingStatus::CannotConfirm)
        .evidence(vec![Evidence::new(
            EvidenceClass::Inference,
            "a candidate",
            EvidenceAnchor::new(AnchorSubject::LineRange, "src/bridge.js", line),
            Some(fingerprint()),
            Severity::MustFix,
        )])
        .fingerprint(fingerprint())
        .build()
        .unwrap()
    }

    #[test]
    fn a_recorded_acceptance_round_trips_and_matches() {
        let store = store_in("ack-roundtrip");
        let finding = candidate("the candidate `status: 200,` on line 148");
        let recorded = acknowledge(
            &store,
            "/work/project",
            &fingerprint(),
            &finding,
            "a real HTTP 200 in an API handler",
            CaseSensitivity::Sensitive,
        )
        .unwrap();
        assert!(recorded.row > 0);
        assert_eq!(
            recorded.acknowledgement.finding_id,
            finding.id.as_str().to_owned()
        );

        let index = AcknowledgementIndex::load(&store, "/work/project").unwrap();
        let matched = index
            .for_finding(&finding, CaseSensitivity::Sensitive)
            .expect("the finding it was made from matches");
        assert_eq!(
            matched.acknowledgement.reason,
            "a real HTTP 200 in an API handler"
        );

        // A different locator is different evidence, and does not match.
        let moved = candidate("the candidate `status: 200,` on line 149");
        assert!(
            index
                .for_finding(&moved, CaseSensitivity::Sensitive)
                .is_none()
        );

        // Another project's index does not see it.
        let other = AcknowledgementIndex::load(&store, "/work/other").unwrap();
        assert!(other.is_empty());
    }

    #[test]
    fn a_finding_the_evidence_settled_is_refused() {
        let store = store_in("ack-refused");
        let settled = FindingBuilder::new(
            AssessmentSource::DeterministicCheck,
            SeverityRationale::BlocksHandOff,
        )
        .title("run the tests")
        .severity(Severity::MustFix)
        .evidence(vec![Evidence::new(
            EvidenceClass::DeterministicCheck,
            "the command ran and ended with exit code 1",
            EvidenceAnchor::new(AnchorSubject::Command, "Cargo.toml", "cargo test"),
            Some(fingerprint()),
            Severity::MustFix,
        )])
        .fingerprint(fingerprint())
        .build()
        .unwrap();
        let error = acknowledge(
            &store,
            "/work/project",
            &fingerprint(),
            &settled,
            "we know",
            CaseSensitivity::Sensitive,
        )
        .unwrap_err();
        assert!(matches!(error, AcknowledgementError::NotAcknowledgeable));
    }

    #[test]
    fn a_finding_with_no_checkable_anchor_cannot_be_bound() {
        let store = store_in("ack-unbindable");
        let model_only = FindingBuilder::new(
            AssessmentSource::ModelAssessment,
            SeverityRationale::for_severity(Severity::ShouldFixFirst).unwrap(),
        )
        .title("Model assessment: something looks incomplete")
        .severity(Severity::ShouldFixFirst)
        .evidence(vec![Evidence::new(
            EvidenceClass::ModelAssessment,
            "summary",
            EvidenceAnchor::model_only("a candidate"),
            Some(fingerprint()),
            Severity::ShouldFixFirst,
        )])
        .fingerprint(fingerprint())
        .build()
        .unwrap();
        let error = acknowledge(
            &store,
            "/work/project",
            &fingerprint(),
            &model_only,
            "I looked",
            CaseSensitivity::Sensitive,
        )
        .unwrap_err();
        assert!(matches!(error, AcknowledgementError::NotBindable));
    }

    #[test]
    fn an_empty_reason_is_refused() {
        let store = store_in("ack-reason");
        let finding = candidate("the candidate `x` on line 1");
        let error = acknowledge(
            &store,
            "/work/project",
            &fingerprint(),
            &finding,
            "   ",
            CaseSensitivity::Sensitive,
        )
        .unwrap_err();
        assert!(matches!(error, AcknowledgementError::NoReason));
    }

    #[test]
    fn a_later_acceptance_of_the_same_identity_wins() {
        let store = store_in("ack-newest");
        let finding = candidate("the candidate `x` on line 1");
        acknowledge(
            &store,
            "/work/project",
            &fingerprint(),
            &finding,
            "first look",
            CaseSensitivity::Sensitive,
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        acknowledge(
            &store,
            "/work/project",
            &fingerprint(),
            &finding,
            "second look",
            CaseSensitivity::Sensitive,
        )
        .unwrap();
        let index = AcknowledgementIndex::load(&store, "/work/project").unwrap();
        let matched = index
            .for_finding(&finding, CaseSensitivity::Sensitive)
            .expect("matches");
        assert_eq!(matched.acknowledgement.reason, "second look");
        assert_eq!(recorded(&store, "/work/project").unwrap().len(), 2);
    }

    #[test]
    fn undo_removes_only_the_named_row() {
        let store = store_in("ack-undo");
        let finding = candidate("the candidate `x` on line 1");
        let first = acknowledge(
            &store,
            "/work/project",
            &fingerprint(),
            &finding,
            "first look",
            CaseSensitivity::Sensitive,
        )
        .unwrap();
        assert!(undo(&store, "/work/project", first.row).unwrap());
        assert!(!undo(&store, "/work/project", first.row).unwrap());
        assert!(recorded(&store, "/work/project").unwrap().is_empty());

        // A row id that names another kind is not deleted by this door.
        let row = store
            .append(RecordKind::Approval, &serde_json::json!({"x": 1}))
            .unwrap();
        assert!(!undo(&store, "/work/project", row).unwrap());
    }
}
