//! Frontend/backend route consistency checker.
//!
//! `P6-T005`'s acceptance:
//!
//! > *Mandatory route-mismatch fixture is identified.*
//! > *Dynamic/unknown routing does not produce false certainty.*
//!
//! # What it detects
//!
//! Frontend code that names backend paths which have no corresponding backend
//! route declaration. This catches broken glue where a frontend expects an
//! endpoint that the backend no longer serves (or never did).
//!
//! # What it reads
//!
//! **Backend routes** come from [`crate::http_routes::RouteReading`], which
//! reads Flask, FastAPI, Express and axum route declarations from source.
//!
//! **Frontend expectations** are read from JavaScript, TypeScript and Vue
//! source files. Four shapes are recognised:
//!
//! | shape | example |
//! |---|---|
//! | `fetch` call | `fetch('/api/users')` |
//! | `axios` call | `axios.get('/api/users')` |
//! | React Router | `<Route path="/users" />` |
//! | Vue Router | `path: '/users'` |
//!
//! Only literal string paths are read. Template literals, variables and
//! concatenated strings are skipped, because SURE has no value to put in the
//! hole and guessing would produce false certainty.
//!
//! # Mini-program page paths
//!
//! A WeChat mini-program writes visitor destinations as `path: '/pages/…'`
//! literals too — share configs (`onShareTimeline`/`onShareAppMessage` returns),
//! tab and menu configurations, `navigateTo` arguments. Those name *pages*, not
//! backend routes, and they are declared in the mini-program's `app.json`
//! (`pages`, and `subPackages[].pages` under each `root`). Both layouts the
//! official tools produce are read: `app.json` at the project root and
//! `app.json` under a one-level subdirectory (`miniprogram/`). A `path:`
//! expectation matching a declared page is not a backend expectation and is
//! skipped here; a `path:` that is not declared remains a candidate, because
//! nothing in the project says what serves it.
//!
//! # What it does not do
//!
//! It does not probe running services — that is `P5-T003`'s work. It reads
//! source on both sides and compares statically. A route whose path is built
//! from a variable, a template literal, or a slot is skipped rather than
//! guessed.
//!
//! It does not follow mount prefixes. A backend route declared on a nested
//! router whose mount point lives in another file is still a route SURE read,
//! and it is included in the comparison by its declared path. The same limit
//! [`crate::http_routes`] states about mounts applies here.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::ActionKind;
use sure_domain::ids::FingerprintId;
use sure_domain::status::{CheckResult, NotCheckedReason};

use crate::candidate_context::classify_path;
use crate::checks::check_id;
use crate::discover::Discovery;
use crate::finding_gravity::{GapKind, Reach, gravity_of};
use crate::http_routes::RouteReading;
use crate::planned_work::{CheckOperation, PlannedWork, PrecomputedEvidence};
use crate::redact::escape_control_characters;
use crate::redact::evidence_excerpt;
use crate::references::is_source_candidate;
use crate::scan::display_path;
use crate::schedule::{CheckProposal, CheckReason, PlanBuilder};

/// A path the frontend expects a backend to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FrontendExpectation {
    path: String,
    file: String,
    line: usize,
    context: String,
}

impl FrontendExpectation {
    /// Whether the path has a slot or placeholder SURE cannot fill.
    fn has_slot(path: &str) -> bool {
        path.contains('{')
            || path.contains('<')
            || path
                .split('/')
                .any(|segment| segment.starts_with(':') && segment.len() > 1)
    }

    /// Whether the path is built from a variable or template literal.
    fn is_not_a_literal(path: &str) -> bool {
        path.contains('`') || path.contains("${") || path.is_empty()
    }

    /// Whether the path looks like it could name a backend request target.
    fn is_request_target(path: &str) -> bool {
        path.starts_with('/')
    }
}

/// The route-consistency checks SURE proposes.
///
/// Built by [`Self::of`], which is the only constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteConsistency {
    proposals: Vec<CheckProposal>,
}

impl RouteConsistency {
    /// What SURE would check about frontend/backend route consistency.
    ///
    /// One proposal per frontend path that has no corresponding backend route.
    /// A project whose frontend and backend agree produces nothing.
    #[must_use]
    pub fn of(discovery: &Discovery) -> Self {
        let backend_reading = RouteReading::of(discovery);
        let mut backend_paths: HashSet<String> = HashSet::new();
        for check in backend_reading.checks() {
            backend_paths.insert(check.route().path().to_owned());
        }
        for not_probed in backend_reading.not_probed() {
            backend_paths.insert(not_probed.route().path().to_owned());
        }
        let page_routes = mini_program_pages(discovery);

        let mut expectations: Vec<FrontendExpectation> = Vec::new();
        scan_frontend_files(discovery, &mut expectations);

        let mut proposals = Vec::new();
        let mut seen_paths: HashSet<String> = HashSet::new();

        for expectation in expectations {
            if seen_paths.contains(&expectation.path) {
                continue;
            }
            seen_paths.insert(expectation.path.clone());

            if backend_paths.contains(&expectation.path) {
                continue;
            }
            // A declared mini-program page is a visitor destination, not a
            // backend route; the share/menu configs that name it cannot be
            // settled as "missing backend" because no backend is involved.
            let route = expectation
                .path
                .split(['?', '#'])
                .next()
                .unwrap_or(expectation.path.as_str());
            if page_routes.contains(route) {
                continue;
            }

            let title = format!(
                "frontend expects backend path `{}` which is not declared",
                escape_control_characters(&expectation.path)
            );
            let reason = CheckReason::CandidateFound {
                path: expectation.file.clone(),
                line: expectation.line,
                context: expectation.context.clone(),
            };
            // A frontend path with no backend route behind it is code standing in
            // for an action the product tells a caller it performs, which is the
            // gap the rule rates `must_fix`. `fixtures/adversarial/route-mismatch`
            // requires exactly that, and requires it while the finding stays an
            // inference: SURE read the two sides and did not run either.
            //
            // Where the expectation was read from is asked rather than assumed,
            // with the same classifier the other detectors use, so an expectation
            // in a test fixture cannot become a `must_fix` about production.
            let reach = Reach::from(classify_path(
                Path::new(&expectation.file),
                &discovery.root,
                None,
            ));
            let gravity = gravity_of(
                &reason,
                EvidenceClass::Inference,
                reach,
                GapKind::SubstitutedAction,
            );
            proposals.push(CheckProposal::new(
                check_id(
                    &expectation.file,
                    &format!("route_consistency{}", expectation.path),
                ),
                title,
                gravity.severity(),
                false,
                EvidenceClass::Inference,
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
    /// **Each proposal is paired with the observation this comparison actually
    /// made**, which is a [`StaticObservation::Candidate`] naming the frontend
    /// file and line the expectation stands on: the comparison is static, both
    /// sides were read, and no request was sent. It is not a `Contradicted`,
    /// and the module comment is where that is decided — the backend route may
    /// be declared in a file SURE did not read, or mounted under a prefix this
    /// comparison does not follow, so *not seen* is not *not there*.
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
    /// A route-consistency check cannot be confirmed as a defect from static
    /// inspection alone — the backend route may be declared in a file SURE did
    /// not read, or mounted under a prefix this module does not follow — so
    /// every proposal becomes a skipped result with
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
        "{} Nothing has settled it: both sides were read and no request was sent, so \
         a route SURE did not find is not a route that is absent.",
        proposal.reason().plain_description()
    )))
}

/// Scan source files for frontend route expectations.
fn scan_frontend_files(discovery: &Discovery, expectations: &mut Vec<FrontendExpectation>) {
    let mut candidates: Vec<&Path> = discovery
        .scan
        .files()
        .map(|entry| entry.path.as_path())
        .filter(|path| is_frontend_source(path))
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
        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            for path in expectations_on_line(line) {
                let context = evidence_excerpt(line);
                expectations.push(FrontendExpectation {
                    path,
                    file: file.clone(),
                    line: line_number,
                    context,
                });
            }
        }
    }
}

/// Visitor routes a WeChat mini-program declares in its `app.json`.
///
/// Reads the two layouts the official tooling produces (`app.json` at the
/// project root, or under a one-level directory such as `miniprogram/`), and
/// returns every declared page as an absolute route (`/pages/home/index`),
/// including pages contributed by `subPackages` under their `root`. A file that
/// does not parse is skipped rather than guessed at: an unreadable declaration
/// means "not declared here", which keeps the candidate instead of inventing an
/// exemption.
fn mini_program_pages(discovery: &Discovery) -> HashSet<String> {
    let mut pages: HashSet<String> = HashSet::new();
    let mut add = |route: &str| {
        let trimmed = route.trim().trim_start_matches('/');
        if !trimmed.is_empty() {
            pages.insert(format!("/{trimmed}"));
        }
    };

    for entry in discovery.scan.files() {
        let path = entry.path.as_path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name != "app.json" || path.components().count() > 2 {
            continue;
        }
        let full = discovery.root.join(path);
        if !is_within_project(&discovery.root, &full) {
            continue;
        }
        let Ok(metadata) = fs::metadata(&full) else {
            continue;
        };
        if metadata.len() > 256 * 1024 {
            continue;
        }
        let Ok(bytes) = fs::read(&full) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let Some(object) = value.as_object() else {
            continue;
        };

        if let Some(list) = object.get("pages").and_then(|v| v.as_array()) {
            for page in list {
                if let Some(page) = page.as_str() {
                    add(page);
                }
            }
        }
        for key in ["subPackages", "subpackages"] {
            let Some(list) = object.get(key).and_then(|v| v.as_array()) else {
                continue;
            };
            for sub in list {
                let Some(sub) = sub.as_object() else {
                    continue;
                };
                let root = sub
                    .get("root")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim_end_matches('/');
                let Some(sub_pages) = sub.get("pages").and_then(|v| v.as_array()) else {
                    continue;
                };
                for page in sub_pages {
                    let Some(page) = page.as_str() else {
                        continue;
                    };
                    if root.is_empty() {
                        add(page);
                    } else {
                        add(&format!("{root}/{page}"));
                    }
                }
            }
        }
    }
    pages
}

/// Whether a file is a frontend source file this module reads.
fn is_frontend_source(path: &Path) -> bool {
    if !is_source_candidate(path) {
        return false;
    }
    let extension = path.extension().map(|e| e.to_string_lossy().to_lowercase());
    matches!(
        extension.as_deref(),
        Some("js" | "jsx" | "ts" | "tsx" | "vue" | "svelte" | "mjs" | "cjs" | "mts" | "cts")
    )
}

/// Every literal path expectation on one line.
fn expectations_on_line(line: &str) -> Vec<String> {
    let mut found = Vec::new();

    // fetch('/path') or fetch("/path")
    for pattern in [
        "fetch(",
        "axios.get(",
        "axios.post(",
        "axios.put(",
        "axios.patch(",
        "axios.delete(",
    ] {
        let mut search_from = 0;
        while let Some(start) = line[search_from..].find(pattern) {
            let after = &line[search_from + start + pattern.len()..];
            if let Some((path, end)) = first_quoted_literal(after)
                && should_consider(&path)
                && !is_concatenated(&after[end..])
            {
                found.push(path);
            }
            search_from += start + 1;
        }
    }

    // <Route path="/path" />  and  path: '/path'
    for pattern in ["path=", "path:"] {
        let mut search_from = 0;
        while let Some(start) = line[search_from..].find(pattern) {
            let after = &line[search_from + start + pattern.len()..];
            if let Some((path, end)) = first_quoted_literal(after)
                && should_consider(&path)
                && !is_concatenated(&after[end..])
            {
                found.push(path);
            }
            search_from += start + 1;
        }
    }

    found
}

/// The first quoted literal in a fragment, if there is one, and the byte
/// index after its closing quote in the original `text`.
///
/// Escaped quotes are skipped, so a literal containing `\"` does not end early.
fn first_quoted_literal(text: &str) -> Option<(String, usize)> {
    let trimmed = text.trim_start();
    let leading = text.len() - trimmed.len();
    let quote = trimmed.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = &trimmed[1..];
    let mut escaped = false;
    for (i, c) in rest.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == quote {
            // Index after the closing quote in the original `text`.
            return Some((rest[..i].to_owned(), leading + 1 + i + 1));
        }
    }
    None
}

/// Whether the text after a quoted literal indicates string concatenation.
///
/// If a `+` appears before any `,` or `)` that would end the first argument,
/// the path is built from variables and should be skipped.
fn is_concatenated(after_quote: &str) -> bool {
    for c in after_quote.chars() {
        if c == ',' || c == ')' {
            return false;
        }
        if c == '+' {
            return true;
        }
    }
    false
}

/// Whether a path extracted from source is one this module compares.
///
/// `false` for template literals, variables, slots, and paths that do not look
/// like request targets.
fn should_consider(path: &str) -> bool {
    if FrontendExpectation::is_not_a_literal(path) {
        return false;
    }
    if FrontendExpectation::has_slot(path) {
        return false;
    }
    if !FrontendExpectation::is_request_target(path) {
        return false;
    }
    true
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
    fn a_project_with_no_frontend_or_backend_produces_nothing() {
        let temp = std::env::temp_dir().join(format!(
            "sure-route-consistency-clean-test-{}-{}",
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
        let consistency = RouteConsistency::of(&discovery);
        assert!(consistency.is_empty());
        assert!(consistency.proposed().is_empty());
        assert!(
            consistency
                .not_checked(&FingerprintId::generate())
                .is_empty()
        );
    }

    #[test]
    fn a_route_mismatch_is_detected() {
        let temp = std::env::temp_dir().join(format!(
            "sure-route-mismatch-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        // Backend serves /api/existing
        std::fs::write(
            temp.join("server.js"),
            "const app = express();\napp.get('/api/existing', handler);\n",
        )
        .unwrap();
        // Frontend calls /api/missing
        std::fs::write(temp.join("client.js"), "fetch('/api/missing');\n").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let consistency = RouteConsistency::of(&discovery);
        assert!(!consistency.is_empty(), "a mismatch should be detected");
        assert_eq!(
            consistency.proposed().len(),
            1,
            "exactly one mismatch should be proposed"
        );

        let proposal = &consistency.proposed()[0];
        assert!(
            proposal.title().contains("/api/missing"),
            "the proposal should name the unmatched path: {}",
            proposal.title()
        );
        assert_eq!(
            proposal.severity(),
            Severity::MustFix,
            "the frontend calls a path no backend declares, and a caller of this \
             project is told the action happens"
        );
        assert!(!proposal.critical());
        assert_eq!(proposal.evidence_class(), EvidenceClass::Inference);
        assert_eq!(proposal.requirements().actions(), &[ActionKind::ReadFile]);
        assert!(!proposal.requirements().runs_project_code());
        assert!(
            proposal.reason().plain_description().contains("client.js"),
            "the reason should anchor to the frontend file: {}",
            proposal.reason().plain_description()
        );
    }

    #[test]
    fn matching_routes_produce_no_mismatch() {
        let temp = std::env::temp_dir().join(format!(
            "sure-route-match-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        // Backend serves /api/users
        std::fs::write(
            temp.join("server.js"),
            "const app = express();\napp.get('/api/users', handler);\n",
        )
        .unwrap();
        // Frontend calls /api/users
        std::fs::write(temp.join("client.js"), "fetch('/api/users');\n").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let consistency = RouteConsistency::of(&discovery);
        assert!(
            consistency.is_empty(),
            "matching routes should produce no mismatch"
        );
    }

    #[test]
    fn dynamic_routes_do_not_produce_false_mismatch() {
        let temp = std::env::temp_dir().join(format!(
            "sure-route-dynamic-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        // Frontend calls a dynamic route
        std::fs::write(temp.join("client.js"), "fetch('/api/items/' + id);\n").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let consistency = RouteConsistency::of(&discovery);
        assert!(
            consistency.is_empty(),
            "dynamic routes should not produce false mismatch"
        );
    }

    #[test]
    fn slotted_routes_do_not_produce_false_mismatch() {
        let temp = std::env::temp_dir().join(format!(
            "sure-route-slot-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        // Frontend uses a slotted path (Vue Router style)
        std::fs::write(temp.join("client.js"), "{ path: '/api/items/:id' }\n").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let consistency = RouteConsistency::of(&discovery);
        assert!(
            consistency.is_empty(),
            "slotted routes should not produce false mismatch"
        );
    }

    #[test]
    fn unparseable_frontend_route_does_not_produce_false_certainty() {
        let temp = std::env::temp_dir().join(format!(
            "sure-route-unparseable-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        // Frontend uses a template literal — not read
        std::fs::write(temp.join("client.js"), "fetch(`/api/items/${id}`);\n").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let consistency = RouteConsistency::of(&discovery);
        assert!(
            consistency.is_empty(),
            "template literals should not produce false certainty"
        );
    }

    #[test]
    fn produced_check_does_not_aggregate_to_local_pass() {
        let fingerprint = FingerprintId::generate();
        let temp = std::env::temp_dir().join(format!(
            "sure-route-agg-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        std::fs::write(
            temp.join("server.js"),
            "const app = express();\napp.get('/api/existing', handler);\n",
        )
        .unwrap();
        std::fs::write(temp.join("client.js"), "fetch('/api/missing');\n").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let consistency = RouteConsistency::of(&discovery);
        assert!(!consistency.is_empty());

        let results = consistency.not_checked(&fingerprint);
        assert_eq!(results.len(), 1);
        let result = &results[0];
        assert_eq!(result.status, CheckStatus::Skipped);
        assert!(!result.status.is_green());
        assert!(
            !result.blocks_green(),
            "a non-critical candidate check that did not run must not block green"
        );
        assert_eq!(
            result.not_checked_reason,
            Some(NotCheckedReason::UnknownReason)
        );
    }

    #[test]
    fn nothing_this_module_builds_is_refused_and_the_plan_holds_everything() {
        let temp = std::env::temp_dir().join(format!(
            "sure-route-plan-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        std::fs::write(
            temp.join("server.js"),
            "const app = express();\napp.get('/api/existing', handler);\n",
        )
        .unwrap();
        std::fs::write(temp.join("client.js"), "fetch('/api/missing');\n").unwrap();

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let consistency = RouteConsistency::of(&discovery);
        assert_eq!(consistency.proposed().len(), 1);

        let mut builder = PlanBuilder::new(
            sure_domain::execution::ExecutionMode::HostConfirmed,
            sure_domain::execution::ExecutionPermissions::inspect_only(),
        );
        consistency.add_to(&mut builder);

        assert!(builder.refused().is_empty());
        let schedule = builder.build();
        assert_eq!(schedule.len(), 1);
        assert!(schedule.duplicates().is_empty());
    }

    #[test]
    fn first_quoted_literal_reads_single_and_double_quotes() {
        assert_eq!(
            first_quoted_literal("'/api/users'"),
            Some(("/api/users".to_owned(), 12))
        );
        assert_eq!(
            first_quoted_literal("\"/api/users\""),
            Some(("/api/users".to_owned(), 12))
        );
    }

    #[test]
    fn first_quoted_literal_skips_escaped_quotes() {
        assert_eq!(
            first_quoted_literal("'/api/\\'users'"),
            Some(("/api/\\'users".to_owned(), 14))
        );
    }

    #[test]
    fn first_quoted_literal_returns_none_for_template_literal() {
        assert_eq!(first_quoted_literal("`/api/users`"), None);
    }

    /// Writes `app.json` and a share config under a fresh temp project and
    /// returns its root.
    fn mini_program_project(
        label: &str,
        app_json_path: &str,
        app_json: &str,
        share_file: &str,
        share_source: &str,
    ) -> std::path::PathBuf {
        let temp = std::env::temp_dir().join(format!(
            "sure-route-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let app_path = temp.join(app_json_path);
        std::fs::create_dir_all(app_path.parent().unwrap()).unwrap();
        std::fs::write(app_path, app_json).unwrap();
        let share_path = temp.join(share_file);
        std::fs::create_dir_all(share_path.parent().unwrap()).unwrap();
        std::fs::write(share_path, share_source).unwrap();
        temp
    }

    #[test]
    fn a_declared_mini_program_page_is_not_a_backend_expectation() {
        // The `miniprogram/` layout the official tools produce, with a page and
        // a sub-package page named by share configs.
        let temp = mini_program_project(
            "mini-pages",
            "miniprogram/app.json",
            r#"{"pages":["pages/home/index"],"subPackages":[{"root":"pkg","pages":["detail/index"]}]}"#,
            "miniprogram/pages/home/index.js",
            "return { title, path: '/pages/home/index' };\n\
             return { title, path: '/pkg/detail/index?from=share' };\n",
        );

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let consistency = RouteConsistency::of(&discovery);
        assert!(
            consistency.is_empty(),
            "declared page routes must not be reported as missing backend routes: {:?}",
            consistency
                .proposed()
                .iter()
                .map(|p| p.title())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_undeclared_path_in_a_mini_program_is_still_a_candidate() {
        let temp = mini_program_project(
            "mini-undeclared",
            "miniprogram/app.json",
            r#"{"pages":["pages/home/index"]}"#,
            "miniprogram/pages/home/other.js",
            "const config = { path: '/api/missing' };\n",
        );

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        let consistency = RouteConsistency::of(&discovery);
        assert_eq!(
            consistency.proposed().len(),
            1,
            "an undeclared path stays a candidate"
        );
        assert!(consistency.proposed()[0].title().contains("/api/missing"));
    }

    #[test]
    fn a_root_app_json_declares_pages_too() {
        let temp = mini_program_project(
            "mini-root",
            "app.json",
            r#"{"pages":["pages/about/index"]}"#,
            "pages/about/index.ts",
            "return { title, path: '/pages/about/index' };\n",
        );

        let discovery =
            crate::discover::discover(&temp, &crate::discover::DiscoverOptions::default()).unwrap();
        assert!(RouteConsistency::of(&discovery).is_empty());
    }

    #[test]
    fn should_consider_rejects_template_literals_and_slots() {
        assert!(!should_consider("`/api/users`"));
        assert!(!should_consider("/api/users/:id"));
        assert!(!should_consider("/api/users/{id}"));
        assert!(!should_consider(""));
        assert!(should_consider("/api/users"));
    }

    #[test]
    fn expectations_on_line_finds_fetch_and_axios() {
        let found = expectations_on_line("fetch('/api/users');");
        assert_eq!(found, vec!["/api/users"]);

        let found = expectations_on_line("axios.get('/api/users');");
        assert_eq!(found, vec!["/api/users"]);

        let found = expectations_on_line("axios.post('/api/users', data);");
        assert_eq!(found, vec!["/api/users"]);
    }

    #[test]
    fn expectations_on_line_finds_react_router_path() {
        let found = expectations_on_line("<Route path=\"/users\" component={Users} />");
        assert_eq!(found, vec!["/users"]);
    }

    #[test]
    fn expectations_on_line_finds_vue_router_path() {
        let found = expectations_on_line("{ path: '/users', component: Users }");
        assert_eq!(found, vec!["/users"]);
    }

    #[test]
    fn expectations_on_line_skips_dynamic_paths() {
        let found = expectations_on_line("fetch('/api/items/' + id);");
        assert!(found.is_empty());
    }

    #[test]
    fn multiple_expectations_on_one_line_are_all_found() {
        let found = expectations_on_line("fetch('/api/a'); fetch('/api/b');");
        assert_eq!(found, vec!["/api/a", "/api/b"]);
    }
}
