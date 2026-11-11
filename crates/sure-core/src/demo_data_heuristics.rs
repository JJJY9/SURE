//! Hard-coded demo-data heuristic scanner.
//!
//! `P6-T004`'s acceptance: *mandatory demo-analytics fixture is identified
//! without blanket constant flagging.*
//!
//! # What it detects
//!
//! Four categories of hard-coded demo or sample data in source files:
//! - Demo analytics values (`ga('create', 'UA-XXXXX-Y')`, `gtag('config', 'G-XXXXXXX')`,
//!   `analytics.track('...')` with literal IDs)
//! - Hard-coded demo datasets (`demoData`, `sampleData`, `fixtureData`, `mockData`
//!   when assigned literals)
//! - Placeholder user/content IDs in production paths (`user_123`, `demo_user`,
//!   `test_user` when used in production context)
//! - Hard-coded chart/dashboard/demo values that look like sample data
//!
//! # What it does not do
//!
//! It does not flag every string or number literal. Only patterns that are
//! clearly demo, sample, or analytics fixtures are reported. A `const
//! MAX_RETRIES: u32 = 3;` or `let name = "alice";` does not match.

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

/// What kind of hard-coded demo-data pattern SURE detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DemoDataCategory {
    /// A hard-coded analytics tracking ID or analytics call with literal args.
    DemoAnalytics,
    /// A variable named as demo/sample/fixture/mock data and assigned a literal.
    DemoDataset,
    /// A placeholder user or content ID used in code.
    PlaceholderUserId,
    /// A hard-coded chart, dashboard, or demo value that looks like sample data.
    HardCodedDemoValue,
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
/// **The order is the report's**: demo_analytics, demo_dataset,
/// placeholder_user_id, hard_coded_demo_value.
///
/// **All four are [`GapKind::UnrealContent`]**, which the rule rates one level
/// below a substituted action: the code here runs and produces the result it
/// says it produces, and what is wrong is that the content is not real.
/// `fixtures/adversarial/demo-analytics/scenario.json` requires
/// `should_fix_first` for all four, and its `forbidden_outcomes` says why the
/// level is not `must_fix` — the concern is a constant presented as a
/// measurement, not a user being told something happened that did not.
const CATEGORIES: &[(DemoDataCategory, CategoryRow)] = &[
    (
        DemoDataCategory::DemoAnalytics,
        CategoryRow {
            gap: GapKind::UnrealContent,
            critical: false,
            evidence_class: EvidenceClass::Inference,
        },
    ),
    (
        DemoDataCategory::DemoDataset,
        CategoryRow {
            gap: GapKind::UnrealContent,
            critical: false,
            evidence_class: EvidenceClass::Inference,
        },
    ),
    (
        DemoDataCategory::PlaceholderUserId,
        CategoryRow {
            gap: GapKind::UnrealContent,
            critical: false,
            evidence_class: EvidenceClass::Inference,
        },
    ),
    (
        DemoDataCategory::HardCodedDemoValue,
        CategoryRow {
            gap: GapKind::UnrealContent,
            critical: false,
            evidence_class: EvidenceClass::Inference,
        },
    ),
];

impl DemoDataCategory {
    /// The readable half of this category's check identifiers.
    const fn tag(self) -> &'static str {
        match self {
            Self::DemoAnalytics => "demo_analytics",
            Self::DemoDataset => "demo_dataset",
            Self::PlaceholderUserId => "placeholder_user_id",
            Self::HardCodedDemoValue => "hard_coded_demo_value",
        }
    }

    /// The phrase a check's title is built from.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::DemoAnalytics => "project contains hard-coded demo analytics values",
            Self::DemoDataset => "project contains hard-coded demo or sample datasets",
            Self::PlaceholderUserId => "project contains placeholder user or content IDs",
            Self::HardCodedDemoValue => "project contains hard-coded demo or chart values",
        }
    }

    /// The phrase a check's title is built from, with context.
    #[must_use]
    pub fn contextual_description(self, context: CandidateContext) -> String {
        let base = match self {
            Self::DemoAnalytics => "project contains hard-coded demo analytics values",
            Self::DemoDataset => "project contains hard-coded demo or sample datasets",
            Self::PlaceholderUserId => "project contains placeholder user or content IDs",
            Self::HardCodedDemoValue => "project contains hard-coded demo or chart values",
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
            Self::DemoAnalytics => matches_demo_analytics(line),
            Self::DemoDataset => matches_demo_dataset(line),
            Self::PlaceholderUserId => matches_placeholder_user_id(line),
            Self::HardCodedDemoValue => matches_hard_coded_demo_value(line),
        }
    }
}

/// Demo analytics indicators: hard-coded tracking IDs and analytics calls.
fn matches_demo_analytics(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("ga('create'")
        || lower.contains("ga(\"create\"")
        || lower.contains("gtag('config'")
        || lower.contains("gtag(\"config\"")
        || lower.contains("analytics.track('")
        || lower.contains("analytics.track(\"")
        || lower.contains("\"ua-")
        || lower.contains("'ua-")
        || lower.contains("\"g-")
        || lower.contains("'g-")
}

/// Hard-coded demo dataset indicators: variables named as demo/sample/fixture/mock data.
fn matches_demo_dataset(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("demodata = [")
        || lower.contains("demodata = {")
        || lower.contains("demodata = \"")
        || lower.contains("demo_data = [")
        || lower.contains("demo_data = {")
        || lower.contains("demo_data = \"")
        || lower.contains("sampledata = [")
        || lower.contains("sampledata = {")
        || lower.contains("sampledata = \"")
        || lower.contains("sample_data = [")
        || lower.contains("sample_data = {")
        || lower.contains("sample_data = \"")
        || lower.contains("fixturedata = [")
        || lower.contains("fixturedata = {")
        || lower.contains("fixturedata = \"")
        || lower.contains("fixture_data = [")
        || lower.contains("fixture_data = {")
        || lower.contains("fixture_data = \"")
        || lower.contains("mockdata = [")
        || lower.contains("mockdata = {")
        || lower.contains("mockdata = \"")
        || lower.contains("mock_data = [")
        || lower.contains("mock_data = {")
        || lower.contains("mock_data = \"")
        || lower.contains("const demodata")
        || lower.contains("let demodata")
        || lower.contains("const demo_data")
        || lower.contains("let demo_data")
        || lower.contains("const sampledata")
        || lower.contains("let sampledata")
        || lower.contains("const sample_data")
        || lower.contains("let sample_data")
        || lower.contains("const fixturedata")
        || lower.contains("let fixturedata")
        || lower.contains("const fixture_data")
        || lower.contains("let fixture_data")
        || lower.contains("const mockdata")
        || lower.contains("let mockdata")
        || lower.contains("const mock_data")
        || lower.contains("let mock_data")
}

/// Placeholder user/content ID indicators.
fn matches_placeholder_user_id(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("demo_user")
        || lower.contains("demouser")
        || lower.contains("test_user")
        || lower.contains("testuser")
        || lower.contains("user_123")
        || lower.contains("user123")
        || lower.contains("guest_user")
        || lower.contains("guestuser")
}

/// Hard-coded demo value indicators: chart/dashboard sample data and placeholder text.
fn matches_hard_coded_demo_value(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("lorem ipsum")
        || lower.contains("chartdata = [")
        || lower.contains("chart_data = [")
        || lower.contains("dashboarddata = [")
        || lower.contains("dashboard_data = [")
        || lower.contains("chartdata = {")
        || lower.contains("chart_data = {")
        || lower.contains("dashboarddata = {")
        || lower.contains("dashboard_data = {")
}

/// Where a hard-coded demo-data pattern was detected.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Detection {
    category: DemoDataCategory,
    file: String,
    line: usize,
    context: String,
    path_context: CandidateContext,
}

/// The checks SURE proposes for detected hard-coded demo-data patterns.
///
/// Built from a discovery result and nothing else — see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoDataHeuristics {
    proposals: Vec<CheckProposal>,
}

impl DemoDataHeuristics {
    /// What SURE would check about hard-coded demo-data patterns in this project.
    ///
    /// **One proposal per detected category**: if a project contains both demo
    /// analytics and demo datasets, two checks are proposed. A project that
    /// contains none produces nothing.
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
            // The severity is the rule's answer, not this table's.
            let gravity = gravity_of(
                &reason,
                row.evidence_class,
                Reach::from(detection.path_context),
                row.gap,
            );
            proposals.push(CheckProposal::new(
                check_id(&detection.file, &format!("demo{}", category.tag())),
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
    /// nothing, and demo data in a file has not been followed to anything a user
    /// sees. It is not a `Holds` (nothing was run), not a `Contradicted` (a
    /// sample record is not proof that the product shows sample data), and not a
    /// `CouldNotRun` (every check here comes from a file that was read).
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
    /// A hard-coded demo-data check cannot be confirmed as a defect from static
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
        "{} Nothing has settled it: this is a pattern in the source, and where the \
         data reaches has not been followed.",
        proposal.reason().plain_description()
    )))
}

/// Scan source files for hard-coded demo-data patterns.
fn scan_source_files(
    discovery: &Discovery,
    graph: &crate::components::ComponentGraph,
    seen: &mut HashSet<DemoDataCategory>,
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
        let listed: Vec<DemoDataCategory> = CATEGORIES.iter().map(|(c, _)| *c).collect();
        assert_eq!(
            listed,
            vec![
                DemoDataCategory::DemoAnalytics,
                DemoDataCategory::DemoDataset,
                DemoDataCategory::PlaceholderUserId,
                DemoDataCategory::HardCodedDemoValue,
            ]
        );
    }

    #[test]
    fn demo_analytics_patterns_match() {
        assert!(matches_demo_analytics("gtag('config', 'G-ABC123DEF');"));
        assert!(matches_demo_analytics("ga('create', 'UA-123456-1');"));
        assert!(matches_demo_analytics("analytics.track('PageView');"));
        assert!(matches_demo_analytics("  const id = \"UA-XXXXX-Y\";"));
        assert!(matches_demo_analytics("let tag = 'G-XXXXXXX';"));
    }

    #[test]
    fn demo_analytics_patterns_do_not_match_every_string() {
        assert!(!matches_demo_analytics("const name = 'alice';"));
        assert!(!matches_demo_analytics("let url = 'https://example.com';"));
        assert!(!matches_demo_analytics("const MAX_RETRIES: u32 = 3;"));
    }

    #[test]
    fn demo_dataset_patterns_match() {
        assert!(matches_demo_dataset("const demoData = [1, 2, 3];"));
        assert!(matches_demo_dataset("let sample_data = { a: 1 };"));
        assert!(matches_demo_dataset("var fixtureData = \"hello\";"));
        assert!(matches_demo_dataset("const mock_data = [];"));
    }

    #[test]
    fn demo_dataset_patterns_do_not_match_ordinary_variables() {
        assert!(!matches_demo_dataset("const userData = [1, 2, 3];"));
        assert!(!matches_demo_dataset("let results = { a: 1 };"));
        assert!(!matches_demo_dataset("const MAX_RETRIES: u32 = 3;"));
    }

    #[test]
    fn placeholder_user_id_patterns_match() {
        assert!(matches_placeholder_user_id("const user = 'demo_user';"));
        assert!(matches_placeholder_user_id("let id = 'test_user';"));
        assert!(matches_placeholder_user_id("const uid = 'user_123';"));
        assert!(matches_placeholder_user_id("let name = 'guestUser';"));
    }

    #[test]
    fn placeholder_user_id_patterns_do_not_match_real_names() {
        assert!(!matches_placeholder_user_id("const user = 'alice';"));
        assert!(!matches_placeholder_user_id("let name = 'bob_smith';"));
        assert!(!matches_placeholder_user_id("const MAX_RETRIES: u32 = 3;"));
    }

    #[test]
    fn hard_coded_demo_value_patterns_match() {
        assert!(matches_hard_coded_demo_value(
            "const text = 'lorem ipsum dolor';"
        ));
        assert!(matches_hard_coded_demo_value(
            "let chartData = [10, 20, 30];"
        ));
        assert!(matches_hard_coded_demo_value(
            "const dashboard_data = { a: 1 };"
        ));
    }

    #[test]
    fn hard_coded_demo_value_patterns_do_not_match_ordinary_constants() {
        assert!(!matches_hard_coded_demo_value(
            "const MAX_RETRIES: u32 = 3;"
        ));
        assert!(!matches_hard_coded_demo_value("let name = 'alice';"));
        assert!(!matches_hard_coded_demo_value("const count = 42;"));
    }

    #[test]
    fn a_project_with_no_patterns_produces_no_detections() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-clean-test-{}-{}",
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
        let scanner = DemoDataHeuristics::of(&discovery);
        assert!(scanner.is_empty());
        assert!(scanner.proposed().is_empty());
        assert!(scanner.not_checked(&FingerprintId::generate()).is_empty());
    }

    #[test]
    fn a_project_with_demo_analytics_produces_a_check() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-analytics-test-{}-{}",
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
            "fn track() { gtag('config', 'G-ABC123DEF'); }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);
        assert!(!scanner.is_empty());
        assert_eq!(scanner.proposed().len(), 1);

        let proposal = &scanner.proposed()[0];
        assert_eq!(
            proposal.title(),
            "project contains hard-coded demo analytics values in production code"
        );
        assert_eq!(
            proposal.severity(),
            Severity::ShouldFixFirst,
            "hard-coded demo values in production code are unreal content a user \
             reads as real: a reliability risk, one level below a substituted \
             action"
        );
        assert!(!proposal.critical());
        assert_eq!(proposal.evidence_class(), EvidenceClass::Inference);
        assert_eq!(proposal.requirements().actions(), &[ActionKind::ReadFile]);
        assert!(!proposal.requirements().runs_project_code());
    }

    #[test]
    fn a_project_with_demo_dataset_produces_a_check() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-dataset-test-{}-{}",
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
            "fn load() { let demoData = [1, 2, 3]; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);
        assert!(!scanner.is_empty());
        assert_eq!(scanner.proposed().len(), 1);

        let proposal = &scanner.proposed()[0];
        assert_eq!(
            proposal.title(),
            "project contains hard-coded demo or sample datasets in production code"
        );
    }

    #[test]
    fn a_project_with_placeholder_user_id_produces_a_check() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-user-test-{}-{}",
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
            "fn get_user() { let user = 'demo_user'; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);
        assert!(!scanner.is_empty());
        assert_eq!(scanner.proposed().len(), 1);

        let proposal = &scanner.proposed()[0];
        assert_eq!(
            proposal.title(),
            "project contains placeholder user or content IDs in production code"
        );
    }

    #[test]
    fn a_project_with_hard_coded_demo_value_produces_a_check() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-value-test-{}-{}",
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
            "fn chart() { let chartData = [10, 20, 30]; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);
        assert!(!scanner.is_empty());
        assert_eq!(scanner.proposed().len(), 1);

        let proposal = &scanner.proposed()[0];
        assert_eq!(
            proposal.title(),
            "project contains hard-coded demo or chart values in production code"
        );
    }

    #[test]
    fn produced_check_does_not_aggregate_to_local_pass() {
        let fingerprint = FingerprintId::generate();
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-agg-test-{}-{}",
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
            "fn track() { gtag('config', 'G-ABC123DEF'); }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);
        assert!(!scanner.is_empty());

        let results = scanner.not_checked(&fingerprint);
        assert_eq!(results.len(), 1);
        let result = &results[0];
        assert_eq!(result.status, CheckStatus::Skipped);
        assert!(!result.status.is_green());
        assert!(
            !result.blocks_green(),
            "a non-critical demo-data check that did not run must not block green"
        );
        assert_eq!(
            result.not_checked_reason,
            Some(NotCheckedReason::UnknownReason)
        );
    }

    #[test]
    fn nothing_this_module_builds_is_refused_and_the_plan_holds_everything() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-plan-test-{}-{}",
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
            "fn track() { gtag('config', 'G-ABC123DEF'); }\nfn load() { let demoData = [1]; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);
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
    fn a_blocked_demo_data_check_stays_in_the_plan() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-blocked-test-{}-{}",
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
            "fn track() { gtag('config', 'G-ABC123DEF'); }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);

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
            "sure-demo-reason-test-{}-{}",
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
            "fn track() { gtag('config', 'G-ABC123DEF'); }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);

        let proposal = scanner.proposed().first().unwrap();
        let reason = proposal.reason();
        assert!(reason.names_something());
        let desc = reason.plain_description();
        assert!(
            desc.contains("gtag('config', 'G-ABC123DEF')"),
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
    fn demo_analytics_in_tests_produces_test_context_title() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-test-ctx-{}-{}",
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
            "fn test_track() { gtag('config', 'G-ABC123DEF'); }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);
        assert_eq!(scanner.proposed().len(), 1);
        assert_eq!(
            scanner.proposed()[0].title(),
            "project contains hard-coded demo analytics values in tests"
        );
    }

    #[test]
    fn demo_analytics_in_src_produces_product_context_title() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-src-ctx-{}-{}",
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
            "fn track() { gtag('config', 'G-ABC123DEF'); }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);
        assert_eq!(scanner.proposed().len(), 1);
        assert_eq!(
            scanner.proposed()[0].title(),
            "project contains hard-coded demo analytics values in production code"
        );
    }

    #[test]
    fn product_context_is_preferred_when_both_test_and_product_exist() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-prefer-prod-{}-{}",
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
            "fn test_track() { gtag('config', 'G-TEST'); }\n",
        )
        .unwrap();
        std::fs::write(
            temp.join("src/lib.rs"),
            "fn track() { gtag('config', 'G-PROD'); }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);
        assert_eq!(scanner.proposed().len(), 1);
        assert_eq!(
            scanner.proposed()[0].title(),
            "project contains hard-coded demo analytics values in production code",
            "Product context should be preferred over Test context"
        );
    }

    #[test]
    fn all_four_categories_can_be_detected_in_one_project() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-all-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(temp.join("src")).unwrap();
        std::fs::write(
            temp.join("src/analytics.rs"),
            "fn track() { gtag('config', 'G-ABC123DEF'); }\n",
        )
        .unwrap();
        std::fs::write(
            temp.join("src/data.rs"),
            "fn load() { let demoData = [1, 2, 3]; }\n",
        )
        .unwrap();
        std::fs::write(
            temp.join("src/user.rs"),
            "fn get() { let user = 'demo_user'; }\n",
        )
        .unwrap();
        std::fs::write(
            temp.join("src/chart.rs"),
            "fn chart() { let chartData = [10, 20, 30]; }\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);
        assert_eq!(scanner.proposed().len(), 4);

        let titles: Vec<&str> = scanner.proposed().iter().map(|p| p.title()).collect();
        assert!(
            titles
                .contains(&"project contains hard-coded demo analytics values in production code")
        );
        assert!(
            titles.contains(
                &"project contains hard-coded demo or sample datasets in production code"
            )
        );
        assert!(
            titles.contains(&"project contains placeholder user or content IDs in production code")
        );
        assert!(
            titles.contains(&"project contains hard-coded demo or chart values in production code")
        );
    }

    #[test]
    fn ordinary_constants_are_not_blanket_flagged() {
        let temp = std::env::temp_dir().join(format!(
            "sure-demo-no-blanket-{}-{}",
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
            "const MAX_RETRIES: u32 = 3;\nlet name = \"alice\";\nlet count = 42;\n",
        )
        .unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let scanner = DemoDataHeuristics::of(&discovery);
        assert!(
            scanner.is_empty(),
            "ordinary constants must not be blanket-flagged"
        );
    }
}
