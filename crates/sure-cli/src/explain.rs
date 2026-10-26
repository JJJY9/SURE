//! `sure explain`: one recorded finding or check result, in plain language.
//!
//! The store holds the documents a run wrote. This command finds one of them —
//! by its stable id, by the row number `sure history` can show, or, with no id,
//! the most recent one — and explains what it says. It never re-runs a check and
//! never turns a stored `CannotConfirm` into a pass.

use std::io::Write;

use serde_json::{Value, json};
use sure_core::diagnostics::Timestamp;
use sure_core::finding::{Finding, FindingStatus};
use sure_core::paths::Paths;
use sure_core::redact::escape_control_characters;
use sure_core::status::{CheckResult, CheckStatus};
use sure_core::store::{DocumentKind, HistoryFilter, RecordKind, Store, StoredRecord};

use crate::commands::Named;
use crate::report::{Failed, Report};

/// How many stored rows one id lookup may scan.
///
/// A lookup by id reads one kind at a time, newest first. The bound is far
/// above the number of findings one machine accumulates in a session; a store
/// that grows past it still answers by row number.
const SCAN_LIMIT: usize = 100_000;

/// What was recorded, decoded as the document it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainKind {
    /// A finding an earlier run left for a person to read.
    Finding(Box<Finding>),
    /// One check's own result.
    CheckResult(Box<CheckResult>),
}

/// What `sure explain` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainReport {
    /// The id the caller asked for, if any.
    pub requested: Option<String>,
    /// The store row that was read.
    pub row: i64,
    /// The project the row is about, as it was recorded.
    pub project_root: Option<String>,
    /// When the row was written, in milliseconds since the epoch.
    pub written_at_ms: i64,
    /// The decoded document.
    pub kind: ExplainKind,
}

impl ExplainReport {
    /// The stable name of the explained document.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match &self.kind {
            ExplainKind::Finding(_) => "finding",
            ExplainKind::CheckResult(_) => "check result",
        }
    }

    /// The document's own id, for a reader or a script.
    #[must_use]
    pub fn id(&self) -> &str {
        match &self.kind {
            ExplainKind::Finding(finding) => finding.id.as_str(),
            ExplainKind::CheckResult(result) => result.id.as_str(),
        }
    }

    /// What a script reads.
    #[must_use]
    pub fn machine(&self) -> Value {
        let mut details = json!({
            "requested": self.requested,
            "row": self.row,
            "project": self.project_root,
            "written_at_ms": self.written_at_ms,
            "written_at": Timestamp::from_millis(self.written_at_ms).to_string(),
            "kind": self.kind_name(),
            "id": self.id(),
        });
        match &self.kind {
            ExplainKind::Finding(finding) => {
                details["finding"] = serde_json::to_value(finding).unwrap_or(Value::Null);
            }
            ExplainKind::CheckResult(result) => {
                details["check_result"] = serde_json::to_value(result).unwrap_or(Value::Null);
            }
        }
        details
    }

    /// Write the human form.
    ///
    /// # Errors
    ///
    /// Any failure from `out`.
    pub fn human(&self, out: &mut impl Write) -> std::io::Result<()> {
        writeln!(
            out,
            "Recorded {} {}",
            self.kind_name(),
            escape_control_characters(self.id())
        )?;
        writeln!(out)?;
        writeln!(
            out,
            "  Recorded at  {}",
            Timestamp::from_millis(self.written_at_ms)
        )?;
        if let Some(project) = &self.project_root {
            writeln!(out, "  Project      {}", escape_control_characters(project))?;
        }
        writeln!(out, "  Store row    {}", self.row)?;
        writeln!(out)?;
        match &self.kind {
            ExplainKind::Finding(finding) => render_finding(finding, out),
            ExplainKind::CheckResult(result) => render_check_result(result, out),
        }
    }
}

fn render_finding(finding: &Finding, out: &mut impl Write) -> std::io::Result<()> {
    writeln!(
        out,
        "  Title        {}",
        escape_control_characters(&finding.title)
    )?;
    writeln!(out, "  Severity     {}", finding.severity.label())?;
    writeln!(
        out,
        "  Status       {}",
        finding_status_label(finding.status)
    )?;
    writeln!(
        out,
        "  Evidence     {}",
        finding.strongest_evidence_class().as_str()
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "  What:    {}",
        escape_control_characters(&finding.explanation)
    )?;
    writeln!(
        out,
        "  Impact:  {}",
        escape_control_characters(&finding.user_impact)
    )?;
    writeln!(
        out,
        "  Next:    {}",
        escape_control_characters(&finding.next_step)
    )?;
    if !finding.evidence.is_empty() {
        writeln!(out)?;
        writeln!(out, "  Evidence:")?;
        for evidence in &finding.evidence {
            writeln!(
                out,
                "    - {} at {} ({})",
                evidence.class.as_str(),
                escape_control_characters(&evidence.anchor.location),
                escape_control_characters(&evidence.anchor.locator)
            )?;
            if !evidence.summary.is_empty() {
                writeln!(
                    out,
                    "      {}",
                    escape_control_characters(&evidence.summary)
                )?;
            }
        }
    }
    Ok(())
}

fn render_check_result(result: &CheckResult, out: &mut impl Write) -> std::io::Result<()> {
    writeln!(
        out,
        "  Title        {}",
        escape_control_characters(&result.title)
    )?;
    writeln!(out, "  Status       {}", check_status_label(result.status))?;
    writeln!(out, "  Severity     {}", result.severity.label())?;
    writeln!(out, "  Evidence     {}", result.evidence_class.as_str())?;
    writeln!(out, "  Critical     {}", result.critical)?;
    if let Some(reason) = result.not_checked_reason {
        writeln!(out)?;
        writeln!(out, "  Not checked: {}", reason.plain_explanation())?;
    } else if !result.reason.is_empty() {
        writeln!(out)?;
        writeln!(
            out,
            "  What:    {}",
            escape_control_characters(&result.reason)
        )?;
    }
    Ok(())
}

fn finding_status_label(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::Open => "Open",
        FindingStatus::Resolved => "Resolved",
        FindingStatus::AcceptedRisk => "Accepted risk",
        FindingStatus::CannotConfirm => "Cannot confirm",
    }
}

fn check_status_label(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "Pass",
        CheckStatus::Fail => "Fail",
        CheckStatus::Warning => "Warning",
        CheckStatus::Skipped => "Skipped",
        CheckStatus::Error => "Error",
        CheckStatus::Unknown => "Unknown",
    }
}

/// Run `sure explain`.
#[must_use]
pub fn explain(id: Option<&str>, named: Named<'_>) -> Report {
    match build(id, named) {
        Ok(report) => Report::Explain(Box::new(report)),
        Err(detail) => Report::Failed(Box::new(Failed {
            command: "explain",
            what: "Nothing was explained.",
            detail,
        })),
    }
}

fn build(id: Option<&str>, named: Named<'_>) -> Result<ExplainReport, String> {
    let paths = Paths::discover_with(named.store, named.settings_file)
        .map_err(|error| error.to_string())?;
    let store_file = paths.store_file();
    if !store_file.is_file() {
        return Err(format!(
            "SURE has recorded nothing at {}. `sure check` does not record a result; \
             `sure repair` and `sure recheck` do.",
            store_file.display()
        ));
    }
    let store = Store::open_at(&store_file).map_err(|error| error.to_string())?;
    let record = match id {
        Some(id) => lookup(&store, id)?,
        None => latest(&store)?,
    };
    report_from_record(id, record)
}

fn lookup(store: &Store, id: &str) -> Result<StoredRecord, String> {
    let id = id.trim();
    if id.is_empty() {
        return Err(
            "No result id was given. Run `sure explain` to explain the most recent \
                    recorded result."
                .to_owned(),
        );
    }
    if let Ok(row) = id.parse::<i64>()
        && let Some(record) = store.record(row).map_err(|error| error.to_string())?
    {
        return Ok(record);
    }
    for document in [DocumentKind::Finding, DocumentKind::CheckResult] {
        let filter = HistoryFilter {
            kind: Some(RecordKind::Document(document)),
            ..HistoryFilter::default()
        };
        let records = store
            .history(&filter, SCAN_LIMIT)
            .map_err(|error| error.to_string())?;
        for record in records {
            let matches = match document {
                DocumentKind::Finding => record
                    .decode::<Finding>()
                    .map(|finding| finding.id.as_str() == id)
                    .map_err(|error| error.to_string())?,
                DocumentKind::CheckResult => record
                    .decode::<CheckResult>()
                    .map(|result| result.id.as_str() == id)
                    .map_err(|error| error.to_string())?,
                _ => false,
            };
            if matches {
                return Ok(record);
            }
        }
    }
    Err(format!(
        "No recorded finding or check result has the id \"{}\". Run `sure explain` with no id \
         to explain the most recent recorded result.",
        escape_control_characters(id)
    ))
}

fn latest(store: &Store) -> Result<StoredRecord, String> {
    let mut newest: Option<StoredRecord> = None;
    for document in [DocumentKind::Finding, DocumentKind::CheckResult] {
        let filter = HistoryFilter {
            kind: Some(RecordKind::Document(document)),
            ..HistoryFilter::default()
        };
        let Some(record) = store
            .history(&filter, 1)
            .map_err(|error| error.to_string())?
            .into_iter()
            .next()
        else {
            continue;
        };
        if newest
            .as_ref()
            .is_none_or(|current| record.written_at_ms > current.written_at_ms)
        {
            newest = Some(record);
        }
    }
    newest.ok_or_else(|| {
        "SURE has recorded no findings or check results yet. `sure repair` and \
         `sure recheck` record their results; `sure check` does not."
            .to_owned()
    })
}

fn report_from_record(
    requested: Option<&str>,
    record: StoredRecord,
) -> Result<ExplainReport, String> {
    let kind = match record.kind {
        RecordKind::Document(DocumentKind::Finding) => ExplainKind::Finding(Box::new(
            record
                .decode::<Finding>()
                .map_err(|error| error.to_string())?,
        )),
        RecordKind::Document(DocumentKind::CheckResult) => ExplainKind::CheckResult(Box::new(
            record
                .decode::<CheckResult>()
                .map_err(|error| error.to_string())?,
        )),
        other => {
            return Err(format!(
                "Store row {} is {}, not a finding or check result. `sure explain` covers \
                 findings and check results; use `sure history show` for sessions and events.",
                record.id,
                other.as_str()
            ));
        }
    };
    Ok(ExplainReport {
        requested: requested.map(ToOwned::to_owned),
        row: record.id,
        project_root: record.project_root,
        written_at_ms: record.written_at_ms,
        kind,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cli::Command;
    use crate::commands::Named;
    use crate::report::Report;
    use sure_core::evidence::{AnchorSubject, Evidence, EvidenceAnchor, EvidenceClass};
    use sure_core::finding::{AssessmentSource, FindingBuilder, FindingStatus, SeverityRationale};
    use sure_core::ids::{CheckId, FingerprintId};
    use sure_core::severity::Severity;
    use sure_core::status::CheckResult;
    use sure_core::store::{DocumentKind, RecordKind, Store};

    fn a_finding() -> Finding {
        let fingerprint = FingerprintId::generate();
        FindingBuilder::new(
            AssessmentSource::DeterministicCheck,
            SeverityRationale::for_severity(Severity::MustFix).unwrap(),
        )
        .title("run the tests")
        .severity(Severity::MustFix)
        .status(FindingStatus::Open)
        .explanation("SURE ran this check and it failed.")
        .user_impact("The tests do not pass.")
        .next_step("Fix the failure and re-check.")
        .fingerprint(fingerprint.clone())
        .evidence(vec![Evidence::new(
            EvidenceClass::DeterministicCheck,
            "the command ran and ended with exit code 1",
            EvidenceAnchor::new(AnchorSubject::Command, "package.json", "npm test"),
            Some(fingerprint),
            Severity::MustFix,
        )])
        .build()
        .unwrap()
    }

    fn a_check_result() -> CheckResult {
        CheckResult::fail(
            CheckId::generate(),
            "run the tests",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            FingerprintId::generate(),
        )
    }

    fn store_with_documents() -> (std::path::PathBuf, i64, i64) {
        let directory = sure_testkit::scratch::directory("sure explain", "store");
        let store = Store::open_at(&directory.join("sure.db")).unwrap();
        let fingerprint = FingerprintId::generate();
        let finding = a_finding();
        let finding_id = finding.id.clone();
        let finding_row = store
            .append_for(
                RecordKind::Document(DocumentKind::Finding),
                &serde_json::to_value(&finding).unwrap(),
                "D:/demo",
                &fingerprint,
            )
            .unwrap();
        let result = a_check_result();
        let result_row = store
            .append_for(
                RecordKind::Document(DocumentKind::CheckResult),
                &serde_json::to_value(&result).unwrap(),
                "D:/demo",
                &fingerprint,
            )
            .unwrap();
        let _ = finding_id;
        (directory, finding_row, result_row)
    }

    #[test]
    fn explain_by_finding_id_says_what_the_finding_says() {
        let (directory, finding_row, _) = store_with_documents();
        let store = Store::open_at(&directory.join("sure.db")).unwrap();
        let finding = store
            .record(finding_row)
            .unwrap()
            .unwrap()
            .decode::<Finding>()
            .unwrap();
        let report = Command::Explain {
            id: Some(finding.id.as_str().to_owned()),
        }
        .report(Named::store(&directory));
        let Report::Explain(explain) = &report else {
            panic!("{report:?}");
        };
        assert_eq!(explain.kind_name(), "finding");
        assert_eq!(explain.id(), finding.id.as_str());
        assert_eq!(explain.row, finding_row);
        let human = report.human_text();
        assert!(human.contains("run the tests"), "{human}");
        assert!(
            human.contains("Cannot confirm") || human.contains("Open"),
            "{human}"
        );
        assert!(human.contains("Fix the failure and re-check."), "{human}");
        assert!(human.contains("package.json"), "{human}");
        assert!(!human.contains("secret"), "{human}");
    }

    #[test]
    fn explain_without_an_id_uses_the_newest_recorded_result() {
        let (directory, _, _) = store_with_documents();
        let report = Command::Explain { id: None }.report(Named::store(&directory));
        let Report::Explain(explain) = &report else {
            panic!("{report:?}");
        };
        assert_eq!(explain.kind_name(), "check result");
        assert!(report.human_text().contains("run the tests"));
    }

    #[test]
    fn explain_accepts_a_store_row_and_refuses_an_unknown_id() {
        let (directory, finding_row, _) = store_with_documents();
        let by_row = Command::Explain {
            id: Some(finding_row.to_string()),
        }
        .report(Named::store(&directory));
        assert!(matches!(by_row, Report::Explain(_)), "{by_row:?}");

        let missing = Command::Explain {
            id: Some("fnd_does_not_exist".to_owned()),
        }
        .report(Named::store(&directory));
        let Report::Failed(failure) = &missing else {
            panic!("{missing:?}");
        };
        assert_eq!(failure.command, "explain");
        assert!(
            failure.detail.contains("No recorded finding"),
            "{failure:?}"
        );
    }

    #[test]
    fn explain_with_no_store_says_nothing_was_recorded() {
        let directory = sure_testkit::scratch::directory("sure explain", "empty");
        let report = Command::Explain { id: None }.report(Named::store(&directory));
        let Report::Failed(failure) = &report else {
            panic!("{report:?}");
        };
        assert!(failure.detail.contains("recorded nothing"), "{failure:?}");
    }
}
