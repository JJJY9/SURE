//! No-op / fake-success heuristic scanner.
//!
//! `P6-T003`'s acceptance: *mandatory fake-email/payment/no-op fixtures produce
//! grounded candidates.*
//!
//! # What it detects
//!
//! Four categories of code that looks like it does real work but may not:
//! - Fake email addresses or domains (`example.com`, `test@`, etc.) used in code
//! - Fake payment tokens / sandbox indicators (`tok_visa`, `pk_test_`, etc.)
//! - No-op function bodies returning constant success values (`Ok(())`, `200`)
//! - Hard-coded success responses for HTTP/email/payment integrations
//!
//! # What it does not do
//!
//! It does not judge whether a hit is a defect. A `test@example.com` in a test
//! fixture is expected, and a `return Ok(());` in a stub is not a product bug.
//! This module finds patterns and records where they were found; what they mean
//! is decided by the caller or by later filters.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::ActionKind;
use sure_domain::ids::FingerprintId;
use sure_domain::status::{CheckResult, NotCheckedReason};

use crate::candidate_context::{CandidateContext, classify_path};
use crate::checks::check_id;
use crate::discover::Discovery;
use crate::finding_gravity::{GapKind, Reach, gravity_of};
use crate::planned_work::{CheckOperation, PlannedWork, PrecomputedEvidence};
use crate::redact::evidence_excerpt;
use crate::references::is_source_candidate;
use crate::scan::display_path;
use crate::schedule::{CheckProposal, CheckReason, PlanBuilder};

/// What kind of no-op / fake-success pattern SURE detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoOpCategory {
    /// A fake email address or domain used in code.
    FakeEmail,
    /// A fake payment token or sandbox indicator.
    FakePayment,
    /// A function body that returns a constant success value with no real work.
    NoOpFunction,
    /// A hard-coded success response for an external integration.
    HardCodedSuccess,
}

/// The weights one category carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CategoryRow {
    /// What kind of gap this category is: the input
    /// [`crate::finding_gravity::gravity_of`] turns into a severity.
    gap: GapKind,
    critical: bool,
    evidence_class: EvidenceClass,
}

/// The categories SURE checks, and what each one's check is.
///
/// **The order is the report's**: fake_email, fake_payment, no_op_function,
/// hard_coded_success.
///
/// **All four are [`GapKind::SubstitutedAction`]**, because in each one
/// something stands where the real thing belongs: a placeholder address where a
/// deliverable one belongs, a sandbox key where a provider call belongs, a
/// constant success return where work belongs, a fixed `200` where an outcome
/// belongs. The fixtures say the same in their own words —
/// `fixtures/adversarial/fake-payment/scenario.json` requires `must_fix` for
/// `FakePayment`, `HardCodedSuccess` and `NoOpFunction`, each with the reason
/// SURE should not treat the code as doing what it says. Whether that reaches a
/// user is not this table's question: the rule reads it from where the pattern
/// was found, so the same category in a test file is a note.
const CATEGORIES: &[(NoOpCategory, CategoryRow)] = &[
    (
        NoOpCategory::FakeEmail,
        CategoryRow {
            gap: GapKind::SubstitutedAction,
            critical: false,
            evidence_class: EvidenceClass::Inference,
        },
    ),
    (
        NoOpCategory::FakePayment,
        CategoryRow {
            gap: GapKind::SubstitutedAction,
            critical: false,
            evidence_class: EvidenceClass::Inference,
        },
    ),
    (
        NoOpCategory::NoOpFunction,
        CategoryRow {
            gap: GapKind::SubstitutedAction,
            critical: false,
            evidence_class: EvidenceClass::Inference,
        },
    ),
    (
        NoOpCategory::HardCodedSuccess,
        CategoryRow {
            gap: GapKind::SubstitutedAction,
            critical: false,
            evidence_class: EvidenceClass::Inference,
        },
    ),
];

impl NoOpCategory {
    /// The readable half of this category's check identifiers.
    const fn tag(self) -> &'static str {
        match self {
            Self::FakeEmail => "fake_email",
            Self::FakePayment => "fake_payment",
            Self::NoOpFunction => "no_op_function",
            Self::HardCodedSuccess => "hard_coded_success",
        }
    }

    /// The phrase a check's title is built from.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::FakeEmail => "project contains fake email addresses or domains",
            Self::FakePayment => "project contains fake payment or sandbox tokens",
            Self::NoOpFunction => "project contains no-op functions that always succeed",
            Self::HardCodedSuccess => "project contains hard-coded success responses",
        }
    }

    /// The phrase a check's title is built from, with context.
    #[must_use]
    pub fn contextual_description(self, context: CandidateContext) -> String {
        let base = match self {
            Self::FakeEmail => "project contains fake email addresses or domains",
            Self::FakePayment => "project contains fake payment or sandbox tokens",
            Self::NoOpFunction => "project contains no-op functions that always succeed",
            Self::HardCodedSuccess => "project contains hard-coded success responses",
        };
        let suffix = match context {
            CandidateContext::Test => " in tests",
            CandidateContext::Example => " in examples",
            CandidateContext::Doc => " in documentation",
            CandidateContext::MockFixture => " in mock fixtures",
            CandidateContext::Product => " in production code",
        };
        format!("{base}{suffix}")
    }

    /// Whether a line matches this category's patterns.
    fn matches(self, line: &str) -> bool {
        match self {
            Self::FakeEmail => matches_fake_email(line),
            Self::FakePayment => matches_fake_payment(line),
            Self::NoOpFunction => matches_no_op_function(line),
            Self::HardCodedSuccess => matches_hard_coded_success(line),
        }
    }
}

/// Fake email indicators: common placeholder domains and test addresses.
fn matches_fake_email(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("@example.com")
        || lower.contains("test@example.com")
        || lower.contains("noreply@example.com")
        || lower.contains("admin@example.com")
        || lower.contains("user@example.com")
        || lower.contains("foo@example.com")
        || lower.contains("bar@example.com")
        || lower.contains("test@localhost")
        || lower.contains("example@example.com")
}

/// Fake payment indicators: sandbox tokens and test credentials.
fn matches_fake_payment(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("tok_visa")
        || lower.contains("tok_mastercard")
        || lower.contains("tok_amex")
        || lower.contains("pk_test_")
        || lower.contains("sk_test_")
        || lower.contains("test_token")
}

/// No-op function indicators: constant success returns without computation.
fn matches_no_op_function(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.contains("return Ok(());")
        || trimmed.contains("return Ok(()),")
        || trimmed.contains("=> Ok(())")
        || trimmed.contains("|| Ok(())")
        || trimmed.contains("return 200;")
        || trimmed.contains("=> 200")
        || trimmed.contains("|| 200")
        || trimmed.contains("return Some(200)")
        || trimmed.contains("return Some(true)")
        || trimmed.contains("=> Some(200)")
        || trimmed.contains("=> Some(true)")
}

/// Hard-coded success response indicators: HTTP or integration success codes.
fn matches_hard_coded_success(line: &str) -> bool {
    let trimmed = line.trim().to_lowercase();
    trimmed.contains(".status(200)")
        || trimmed.contains("status(200)")
        || trimmed.contains("statuscode: 200")
        || trimmed.contains("status_code: 200")
        || trimmed.contains("httpresponse::ok")
        || trimmed.contains("response::ok")
        || trimmed.contains("res.sendstatus(200)")
        || trimmed.contains("status: 200")
}

/// Where a no-op / fake-success pattern was detected.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Detection {
    category: NoOpCategory,
    file: String,
    line: usize,
    context: String,
    path_context: CandidateContext,
}

/// The checks SURE proposes for detected no-op / fake-success patterns.
///
/// Built from a discovery result and nothing else — see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoOpHeuristics {
    proposals: Vec<CheckProposal>,
}

impl NoOpHeuristics {
    /// What SURE would check about no-op / fake-success patterns in this project.
    ///
    /// **One proposal per detected category**: if a project contains both fake
    /// email addresses and no-op functions, two checks are proposed. A project
    /// that contains none produces nothing.
    #[must_use]
    pub fn of(discovery: &Discovery) -> Self {
        let mut detections: Vec<Detection> = Vec::new();
        let mut seen = HashSet::new();

        let graph = crate::components::ComponentGraph::of(discovery);
        scan_source_files(discovery, &graph, &mut seen, &mut detections);

        // Build proposals, one per category, using the first detection as the
        // reason's anchor. Prefer a Product-context detection when one exists,
        // because a candidate in production code is the more significant claim.
        let mut proposals = Vec::new();
        for &(category, row) in CATEGORIES {
            let detection = detections
                .iter()
                .find(|d| d.category == category && d.path_context == CandidateContext::Product)
                .or_else(|| detections.iter().find(|d| d.category == category));
            let Some(detection) = detection else {
                continue;
            };
            let reason = CheckReason::CandidateFound {
                path: detection.file.clone(),
                line: detection.line,
                context: detection.context.clone(),
            };
            // The severity is the rule's answer, not this table's: what a
            // fake-success pattern is worth depends on where it stands as well as
            // on what it is.
            let gravity = gravity_of(
                &reason,
                row.evidence_class,
                Reach::from(detection.path_context),
                row.gap,
            );
            proposals.push(CheckProposal::new(
                check_id(&detection.file, &format!("noop{}", category.tag())),
                category.contextual_description(detection.path_context),
                gravity.severity(),
                row.critical,
                row.evidence_class,
                reason,
                &[ActionKind::ReadFile],
            ));
        }

        // Stable order, so two runs over one project cannot produce two plans.
        proposals.sort_by(|a, b| a.id().as_str().cmp(b.id().as_str()));

        Self { proposals }
    }

    /// The checks SURE would run, in no particular order.
    #[must_use]
    pub fn proposed(&self) -> &[CheckProposal] {
        &self.proposals
    }

    /// Whether there is nothing to check.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty()
    }

    /// Hands every proposal to a plan builder.
    ///
    /// **Each proposal is paired with the observation this scanner actually
    /// made**, which is a [`StaticObservation::Candidate`] naming the file and
    /// line the pattern stands on: this module reads source files and starts
    /// nothing, and a handler that looks like it does nothing has not been
    /// watched doing nothing. It is not a `Holds` (nothing was run), not a
    /// `Contradicted` (a pattern that looks like a no-op is not proof of one),
    /// and not a `CouldNotRun` (every check here comes from a file that was
    /// read).
    ///
    /// [`StaticObservation::Candidate`]: crate::planned_work::StaticObservation::Candidate
    pub fn add_to(&self, builder: &mut PlanBuilder) {
        for proposal in &self.proposals {
            let work = PlannedWork::new(proposal.clone(), observation_of(proposal));
            if let Err(refusal) = builder.propose(work) {
                debug_assert!(
                    builder.refused().contains(&refusal),
                    "the builder returned a refusal it did not record"
                );
            }
        }
    }

    /// One skipped result per proposed check.
    ///
    /// A no-op / fake-success check cannot be confirmed as a defect from static
    /// inspection alone, so every proposal becomes a skipped result with
    /// [`NotCheckedReason::UnknownReason`].
    #[must_use]
    pub fn not_checked(&self, project_fingerprint: &FingerprintId) -> Vec<CheckResult> {
        self.proposals
            .iter()
            .map(|proposal| {
                CheckResult::not_run(
                    proposal.id().clone(),
                    proposal.title().to_owned(),
                    proposal.severity(),
                    proposal.critical(),
                    NotCheckedReason::UnknownReason,
                    project_fingerprint.clone(),
                )
            })
            .collect()
    }
}

/// The work beside one proposal: the reading that produced it, and no more.
///
/// The sentence is [`CheckReason::plain_description`] — the same rendering the
/// report prints — with this module's own clause after it, so the check's
/// evidence and its reason name one place rather than two that agree today.
fn observation_of(proposal: &CheckProposal) -> CheckOperation {
    CheckOperation::Precomputed(PrecomputedEvidence::candidate(format!(
        "{} Nothing has settled it: this is a pattern in the source, and no run has \
         watched the code behave.",
        proposal.reason().plain_description()
    )))
}

/// Scan source files for no-op / fake-success patterns.
fn scan_source_files(
    discovery: &Discovery,
    graph: &crate::components::ComponentGraph,
    seen: &mut HashSet<NoOpCategory>,
    detections: &mut Vec<Detection>,
) {
    let mut candidates: Vec<&Path> = discovery
        .scan
        .files()
        .map(|entry| entry.path.as_path())
        .filter(|path| is_source_candidate(path))
        .collect();
    candidates.sort_unstable();

    let mut files_read = 0_usize;
    let mut bytes_read = 0_u64;

    for path in candidates {
        if files_read >= 512 || bytes_read > 16 * 1024 * 1024 {
            break;
        }

        let full = discovery.root.join(path);
        if !is_within_project(&discovery.root, &full) {
            continue;
        }
        let Ok(metadata) = fs::metadata(&full) else {
            continue;
        };
        if metadata.len() > 1024 * 1024 {
            continue;
        }
        let Ok(bytes) = fs::read(&full) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };

        files_read += 1;
        bytes_read = bytes_read.saturating_add(metadata.len());

        let file = display_path(path);
        let path_context = classify_path(path, &discovery.root, Some(graph));
        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            for &(category, _) in CATEGORIES {
                if seen.contains(&category) {
                    continue;
                }
                if category.matches(line) {
                    let mut context = evidence_excerpt(line);
                    if context.len() > 120 {
                        context.truncate(120);
                        context.push_str("...");
                    }
                    seen.insert(category);
                    detections.push(Detection {
                        category,
                        file: file.clone(),
                        line: line_number,
                        context,
                        path_context,
                    });
                    break;
                }
            }
        }
    }
}

/// Whether a resolved path is still inside the project root.
///
/// The scan module already promises containment and refuses symlinks, but this
/// is a cheap second lock on the door: a path that climbs out with `..` or that
/// resolves to something outside the root is not read.
fn is_within_project(root: &Path, full: &Path) -> bool {
    let Ok(root_canon) = std::fs::canonicalize(root) else {
        return false;
    };
    let Ok(full_canon) = std::fs::canonicalize(full) else {
        return false;
    };
    full_canon.starts_with(&root_canon)
        && full_canon.components().count() > root_canon.components().count()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sure_domain::severity::Severity;
    use sure_domain::status::{CheckStatus, NotCheckedReason};

    #[test]
    fn the_table_covers_every_category_exactly_once() {
        let listed: Vec<NoOpCategory> = CATEGORIES.iter().map(|(c, _)| *c).collect();
        assert_eq!(
            listed,
            vec![
                NoOpCategory::FakeEmail,
                NoOpCategory::FakePayment,
                NoOpCategory::NoOpFunction,
                NoOpCategory::HardCodedSuccess,
            ]
        );
    }

    #[test]
    fn fake_email_patterns_match() {
        assert!(matches_fake_email("const email = \"test@example.com\";"));
        assert!(matches_fake_email("let to = \"noreply@example.com\";"));
        assert!(matches_fake_email("user: admin@example.com"));
        assert!(matches_fake_email("foo@example.com"));
    }

    #[test]
    fn fake_email_patterns_do_not_match_real_domains() {
        assert!(!matches_fake_email("const email = \"hello@github.com\";"));
        assert!(!matches_fake_email("contact@anthropic.com"));
    }

    #[test]
    fn fake_payment_patterns_match() {
        assert!(matches_fake_payment("const token = \"tok_visa\";"));
        assert!(matches_fake_payment("pk_test_1234567890abcdef"));
        assert!(matches_fake_payment("sk_test_1234567890abcdef"));
        assert!(matches_fake_payment("let t = \"test_token\";"));
    }

    #[test]
    fn fake_payment_patterns_do_not_match_bare_sandbox() {
        assert!(!matches_fake_payment("const env = \"sandbox\";"));
        assert!(!matches_fake_payment("run in sandbox mode"));
    }

    #[test]
    fn no_op_function_patterns_match() {
        assert!(matches_no_op_function("    return Ok(());"));
        assert!(matches_no_op_function("|| Ok(())"));
        assert!(matches_no_op_function("=> Ok(())"));
        assert!(matches_no_op_function("    return 200;"));
        assert!(matches_no_op_function("=> 200"));
    }

    #[test]
    fn hard_coded_success_patterns_match() {
        assert!(matches_hard_coded_success("    res.status(200);"));
        assert!(matches_hard_coded_success("HttpResponse::Ok()"));
        assert!(matches_hard_coded_success("statusCode: 200"));
    }

    #[test]
    fn a_project_with_no_patterns_produces_no_detections() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-clean-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(temp.join("main.rs"), "fn main() {}").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);
        assert!(scanner.is_empty());
        assert!(scanner.proposed().is_empty());
        assert!(scanner.not_checked(&FingerprintId::generate()).is_empty());
    }

    #[test]
    fn a_project_with_fake_email_produces_a_check() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-email-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(
            temp.join("main.rs"),
            "fn send_email() { let to = \"test@example.com\"; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);
        assert!(!scanner.is_empty());
        assert_eq!(scanner.proposed().len(), 1);

        let proposal = &scanner.proposed()[0];
        assert_eq!(
            proposal.title(),
            "project contains fake email addresses or domains in production code"
        );
        assert_eq!(
            proposal.severity(),
            Severity::MustFix,
            "a placeholder address in production code is an action standing in for \
             the real one, and the rule says do not hand that off"
        );
        assert!(
            !proposal.critical(),
            "the rule sets a severity and never a criticality: whether a verdict is \
             forbidden is a separate question and this detector does not answer it"
        );
        assert_eq!(
            proposal.evidence_class(),
            EvidenceClass::Inference,
            "the severity is earned by where the finding is anchored, not by \
             relabelling a pattern guess as an observation"
        );
        assert_eq!(proposal.requirements().actions(), &[ActionKind::ReadFile]);
        assert!(!proposal.requirements().runs_project_code());
    }

    #[test]
    fn a_project_with_fake_payment_produces_a_check() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-payment-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(
            temp.join("main.rs"),
            "fn charge() { let token = \"tok_visa\"; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);
        assert!(!scanner.is_empty());
        assert_eq!(scanner.proposed().len(), 1);

        let proposal = &scanner.proposed()[0];
        assert_eq!(
            proposal.title(),
            "project contains fake payment or sandbox tokens in production code"
        );
    }

    #[test]
    fn a_project_with_no_op_function_produces_a_check() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-fn-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(temp.join("main.rs"), "fn process() { return Ok(()); }\n").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);
        assert!(!scanner.is_empty());
        assert_eq!(scanner.proposed().len(), 1);

        let proposal = &scanner.proposed()[0];
        assert_eq!(
            proposal.title(),
            "project contains no-op functions that always succeed in production code"
        );
    }

    #[test]
    fn a_project_with_hard_coded_success_produces_a_check() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-success-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(temp.join("main.rs"), "fn handler() { res.status(200); }\n").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);
        assert!(!scanner.is_empty());
        assert_eq!(scanner.proposed().len(), 1);

        let proposal = &scanner.proposed()[0];
        assert_eq!(
            proposal.title(),
            "project contains hard-coded success responses in production code"
        );
    }

    #[test]
    fn produced_check_does_not_aggregate_to_local_pass() {
        let fingerprint = FingerprintId::generate();
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-agg-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(
            temp.join("main.rs"),
            "fn send() { let e = \"test@example.com\"; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);
        assert!(!scanner.is_empty());

        let results = scanner.not_checked(&fingerprint);
        assert_eq!(results.len(), 1);
        let result = &results[0];
        assert_eq!(result.status, CheckStatus::Skipped);
        assert!(!result.status.is_green());
        assert!(
            !result.blocks_green(),
            "a non-critical no-op check that did not run must not block green"
        );
        assert_eq!(
            result.not_checked_reason,
            Some(NotCheckedReason::UnknownReason)
        );
    }

    #[test]
    fn nothing_this_module_builds_is_refused_and_the_plan_holds_everything() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-plan-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(
            temp.join("main.rs"),
            "fn a() { let e = \"test@example.com\"; }\nfn b() { let t = \"tok_visa\"; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);
        assert_eq!(scanner.proposed().len(), 2);

        let mut builder = PlanBuilder::new(
            sure_domain::execution::ExecutionMode::HostConfirmed,
            sure_domain::execution::ExecutionPermissions::inspect_only(),
        );
        scanner.add_to(&mut builder);

        assert!(builder.refused().is_empty());
        let schedule = builder.build();
        assert_eq!(schedule.len(), 2);
        assert!(schedule.duplicates().is_empty());
    }

    #[test]
    fn a_blocked_no_op_check_stays_in_the_plan() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-blocked-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(
            temp.join("main.rs"),
            "fn send() { let e = \"test@example.com\"; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);

        let mut builder = PlanBuilder::new(
            sure_domain::execution::ExecutionMode::InspectOnly,
            sure_domain::execution::ExecutionPermissions::inspect_only(),
        );
        scanner.add_to(&mut builder);

        let schedule = builder.build();
        assert_eq!(schedule.len(), 1);
        assert_eq!(schedule.blocked().count(), 0);

        let check = &schedule.checks()[0];
        assert_eq!(
            check.proposal().requirements().actions(),
            &[ActionKind::ReadFile]
        );
        assert!(check.proposal().requirements().is_inspection_only());
        assert!(check.may_run());
    }

    #[test]
    fn candidate_found_reason_names_something_and_includes_context() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-reason-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(
            temp.join("main.rs"),
            "fn send() { let e = \"test@example.com\"; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);

        let proposal = scanner.proposed().first().unwrap();
        let reason = proposal.reason();
        assert!(reason.names_something());
        let desc = reason.plain_description();
        assert!(
            desc.contains("test@example.com"),
            "reason should include context: {desc}"
        );
        assert!(
            desc.contains("main.rs"),
            "reason should include file: {desc}"
        );
        assert!(
            desc.contains("line 1"),
            "reason should include line: {desc}"
        );
    }

    #[test]
    fn fake_email_in_tests_produces_test_context_title() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-test-ctx-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(temp.join("tests")).unwrap();
        std::fs::write(
            temp.join("tests/foo.rs"),
            "fn test_send() { let e = \"test@example.com\"; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);
        assert_eq!(scanner.proposed().len(), 1);
        assert_eq!(
            scanner.proposed()[0].title(),
            "project contains fake email addresses or domains in tests"
        );
    }

    #[test]
    fn fake_email_in_src_produces_product_context_title() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-src-ctx-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(temp.join("src")).unwrap();
        std::fs::write(
            temp.join("src/lib.rs"),
            "fn send() { let e = \"test@example.com\"; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);
        assert_eq!(scanner.proposed().len(), 1);
        assert_eq!(
            scanner.proposed()[0].title(),
            "project contains fake email addresses or domains in production code"
        );
    }

    #[test]
    fn product_context_is_preferred_when_both_test_and_product_exist() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-prefer-prod-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(temp.join("tests")).unwrap();
        std::fs::create_dir_all(temp.join("src")).unwrap();
        std::fs::write(
            temp.join("tests/foo.rs"),
            "fn test_send() { let e = \"test@example.com\"; }\n",
        )
        .unwrap();
        std::fs::write(
            temp.join("src/lib.rs"),
            "fn send() { let e = \"admin@example.com\"; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);
        assert_eq!(scanner.proposed().len(), 1);
        assert_eq!(
            scanner.proposed()[0].title(),
            "project contains fake email addresses or domains in production code",
            "Product context should be preferred over Test context"
        );
    }

    #[test]
    fn all_four_categories_can_be_detected_in_one_project() {
        let temp = std::env::temp_dir().join(format!(
            "sure-noop-all-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(temp.join("src")).unwrap();
        std::fs::write(
            temp.join("src/email.rs"),
            "fn send() { let to = \"test@example.com\"; }\n",
        )
        .unwrap();
        std::fs::write(
            temp.join("src/payment.rs"),
            "fn charge() { let token = \"tok_visa\"; }\n",
        )
        .unwrap();
        std::fs::write(temp.join("src/worker.rs"), "fn work() { return Ok(()); }\n").unwrap();
        std::fs::write(
            temp.join("src/handler.rs"),
            "fn handle() { res.status(200); }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = NoOpHeuristics::of(&discovery);
        assert_eq!(scanner.proposed().len(), 4);

        let titles: Vec<&str> = scanner.proposed().iter().map(|p| p.title()).collect();
        assert!(
            titles.contains(&"project contains fake email addresses or domains in production code")
        );
        assert!(
            titles.contains(&"project contains fake payment or sandbox tokens in production code")
        );
        assert!(
            titles.contains(
                &"project contains no-op functions that always succeed in production code"
            )
        );
        assert!(
            titles.contains(&"project contains hard-coded success responses in production code")
        );
    }
}
